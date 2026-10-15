import type { IDBPDatabase } from 'idb';
import type { SendMessageRequest } from '../../../shared/contracts/messages';
import type { CryptoSessionRecord, EncryptedCacheRecord, JsonSetting, LeaseSetting, LocalDbSchema, PendingOutboxRecord } from '../../storage/schema';
import { LocalStorageError, normalizeStorageError } from '../../storage/errors';
import { assertLeaseRecord, type CryptoFence, withCryptoLocks } from '../../storage/locks';
import { encryptRetryMaterial } from '../../storage/retry-material';
import { outgoingCacheKey, sealMessageCacheRecord } from '../../storage/message-cache';
import { parseSenderSequenceState, senderSequenceSettingKey } from '../../storage/sender-sequence';
import { ratchetEncrypt } from '../double-ratchet/core';
import type { DoubleRatchetState } from '../double-ratchet/types';
import { conversationMessageAad } from '../local-state/aad';
import { assertEstablishedRatchetSession, disposeRatchetState, loadRatchetState, wrapRatchetCore } from '../local-state/ratchet-store';
import { ratchetMessageToEnvelope } from '../local-state/wire';
import { sessionMessageAad } from '../session-establishment/aad';
import type { EstablishedAtomicTarget } from './atomic-send';
import { frameAuthenticatedMessageContent } from '../../chat/content';

export type EstablishedBatchMessageInput = {
  client_message_id: string;
  plaintext: Uint8Array;
  recovery_envelopes: SendMessageRequest['recovery_envelopes'];
  attachment_ids?: readonly string[];
};

export type EstablishedBatchSendInput = {
  chat_id: string;
  sender_user_id: string;
  sender_device_id: string;
  targets: readonly EstablishedAtomicTarget[];
  messages: readonly EstablishedBatchMessageInput[];
  allocate_sender_sequence?: boolean;
};

type SessionLane = {
  target: EstablishedAtomicTarget;
  snapshot: CryptoSessionRecord;
  state: DoubleRatchetState;
};

type LocalSidecar = {
  created_at: string;
  encrypted_retry_material: Uint8Array;
  outgoing_cache: EncryptedCacheRecord;
};

/**
 * Fast path for one or more logical messages when every recipient already has
 * an ESTABLISHED pairwise session.
 *
 * Each pairwise lock and ratchet state is loaded once for the whole local
 * group. Messages advance the chain strictly M1 -> M2 -> ... in memory and
 * only the final ratchet state is wrapped/persisted.
 *
 * When allocate_sender_sequence=true, contiguous transport ordering numbers
 * are allocated inside the SAME IndexedDB transaction that persists the final
 * ratchet state, outbox records and encrypted local cache. A crash therefore
 * cannot consume a sender sequence without a durable ciphertext/outbox.
 */
export async function prepareAtomicEstablishedMessageBatch(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  rawInput: EstablishedBatchSendInput,
): Promise<PendingOutboxRecord[] | null> {
  const input = { ...rawInput, messages: rawInput.messages.map(message => ({ ...message,
    plaintext: frameAuthenticatedMessageContent(message.plaintext, { ...rawInput, client_message_id: message.client_message_id }),
  })) };
  if (input.messages.length === 0) return [];
  const targets = normalizeTargets(input.sender_device_id, input.targets);
  const ids = new Set<string>();
  for (const message of input.messages) {
    if (ids.has(message.client_message_id)) throw new LocalStorageError('CORRUPT_STATE', 'Duplicate client_message_id in established send batch');
    ids.add(message.client_message_id);
    if ((message.attachment_ids?.length ?? 0) > 0) return null;
  }

  const existing = await Promise.all(input.messages.map((message) => db.get('pending_outbox', message.client_message_id)));
  if (existing.some(Boolean)) return null;

  const baseNow = Date.now();
  const sidecars = await Promise.all(input.messages.map(async (message, index): Promise<LocalSidecar> => {
    const createdAt = new Date(baseNow + index).toISOString();
    const [encryptedRetryMaterial, outgoingCache] = await Promise.all([
      encryptRetryMaterial(masterKey, {
        chat_id: input.chat_id,
        sender_device_id: input.sender_device_id,
        client_message_id: message.client_message_id,
      }, message.plaintext),
      sealMessageCacheRecord(masterKey, input.chat_id, outgoingCacheKey(message.client_message_id), {
        direction: 'OUTGOING',
        message_id: null,
        client_message_id: message.client_message_id,
        sender_user_id: input.sender_user_id,
        sender_device_id: input.sender_device_id,
        created_at: createdAt,
        revision: 0,
      }, message.plaintext),
    ]);
    return { created_at: createdAt, encrypted_retry_material: encryptedRetryMaterial, outgoing_cache: outgoingCache };
  }));

  const lockNames = targets.map((target) => pairLock(input.sender_device_id, target.recipient_device_id));
  return withCryptoLocks(db, lockNames, async (fences) => {
    const lanes: SessionLane[] = [];
    try {
      const loaded = await Promise.all(targets.map(async (target): Promise<SessionLane> => {
        const snapshot = await db.get('sessions', target.session_id);
        if (!snapshot) throw new LocalStorageError('CORRUPT_STATE', `Missing ratchet session ${target.session_id}`);
        const expectedLock = pairLock(input.sender_device_id, target.recipient_device_id);
        if (snapshot.local_device_id !== input.sender_device_id
          || snapshot.remote_device_id !== target.recipient_device_id
          || snapshot.lock_name !== expectedLock) {
          throw new LocalStorageError('CORRUPT_STATE', 'Pairwise ratchet session identity does not match established batch target');
        }
        assertEstablishedRatchetSession(snapshot);
        const state = await loadRatchetState(db, masterKey, snapshot);
        return { target, snapshot, state };
      }));
      lanes.push(...loaded);

      const outboxes: PendingOutboxRecord[] = [];
      for (let messageIndex = 0; messageIndex < input.messages.length; messageIndex += 1) {
        const message = input.messages[messageIndex]!;
        const sidecar = sidecars[messageIndex]!;
        const envelopes: SendMessageRequest['envelopes'] = [];

        for (const lane of lanes) {
          const aad = sessionMessageAad(
            conversationMessageAad(
              input.chat_id,
              input.sender_user_id,
              input.sender_device_id,
              lane.target.recipient_user_id,
              lane.target.recipient_device_id,
            ),
            lane.snapshot.pqxdh_associated_data,
            lane.snapshot.session_id,
          );
          const encrypted = ratchetEncrypt(lane.state, message.plaintext, aad);
          disposeRatchetState(lane.state);
          lane.state = encrypted.state;
          envelopes.push(ratchetMessageToEnvelope(
            encrypted.message,
            lane.target.recipient_user_id,
            lane.target.recipient_device_id,
            lane.snapshot.session_id,
          ));
        }

        outboxes.push({
          client_message_id: message.client_message_id,
          chat_id: input.chat_id,
          sender_device_id: input.sender_device_id,
          request: {
            client_message_id: message.client_message_id,
            envelopes,
            recovery_envelopes: [...message.recovery_envelopes],
            attachment_ids: [...(message.attachment_ids ?? [])],
          },
          encrypted_retry_material: sidecar.encrypted_retry_material,
          status: 'PENDING',
          attempts: 0,
          created_at: sidecar.created_at,
          updated_at: sidecar.created_at,
        });
      }

      const wrappedFinalStates = await Promise.all(lanes.map((lane) => wrapRatchetCore(masterKey, lane.snapshot, lane.state)));
      await commitEstablishedBatch(
        db,
        lanes,
        wrappedFinalStates,
        fences,
        outboxes,
        sidecars.map((sidecar) => sidecar.outgoing_cache),
        input.chat_id,
        input.sender_device_id,
        input.allocate_sender_sequence === true,
      );
      return outboxes;
    } finally {
      for (const lane of lanes) disposeRatchetState(lane.state);
    }
  });
}

async function commitEstablishedBatch(
  db: IDBPDatabase<LocalDbSchema>,
  lanes: readonly SessionLane[],
  wrappedFinalStates: readonly { state_ciphertext: Uint8Array; state_nonce: Uint8Array }[],
  fences: readonly CryptoFence[],
  outboxes: readonly PendingOutboxRecord[],
  outgoingCaches: readonly EncryptedCacheRecord[],
  chatId: string,
  senderDeviceId: string,
  allocateSenderSequence: boolean,
): Promise<void> {
  if (outboxes.length !== outgoingCaches.length) throw new LocalStorageError('CORRUPT_STATE', 'Established batch local sidecar count mismatch');
  try {
    const tx = db.transaction(['sessions', 'settings', 'pending_outbox', 'encrypted_cache'], 'readwrite');
    const settings = tx.objectStore('settings');
    for (const fence of fences) {
      if (fence.kind === 'lease') {
        const stored = await settings.get(fence.lease_key);
        const lease = stored?.kind === 'lease' ? stored as LeaseSetting : undefined;
        assertLeaseRecord(lease, fence);
      }
    }

    if (allocateSenderSequence) {
      const key = senderSequenceSettingKey(chatId, senderDeviceId);
      const stored = await settings.get(key);
      const state = stored?.kind === 'json' ? parseSenderSequenceState(stored.value) : null;
      if (!state) {
        tx.abort();
        throw new LocalStorageError('CORRUPT_STATE', 'Sender sequence allocator must be seeded before streaming send');
      }
      let lastAllocated = state.last_allocated;
      for (const outbox of outboxes) {
        lastAllocated += 1;
        outbox.request.sender_sequence = lastAllocated;
      }
      await settings.put({
        key,
        kind: 'json',
        value: { version: 1, last_allocated: lastAllocated },
      } satisfies JsonSetting);
    }

    const outboxStore = tx.objectStore('pending_outbox');
    for (const outbox of outboxes) {
      if (await outboxStore.get(outbox.client_message_id)) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'client_message_id appeared before established batch commit');
      }
    }

    const sessions = tx.objectStore('sessions');
    const updatedAt = outboxes[outboxes.length - 1]!.updated_at;
    for (let index = 0; index < lanes.length; index += 1) {
      const lane = lanes[index]!;
      const wrapped = wrappedFinalStates[index]!;
      const current = await sessions.get(lane.snapshot.session_id);
      if (!current || current.state_version !== lane.snapshot.state_version || current.establishment_state !== 'ESTABLISHED') {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Established pairwise ratchet changed before batch commit');
      }
      await sessions.put({
        ...lane.snapshot,
        state_ciphertext: wrapped.state_ciphertext,
        state_nonce: wrapped.state_nonce,
        state_version: lane.snapshot.state_version + 1,
        updated_at: updatedAt,
      });
    }

    const cacheStore = tx.objectStore('encrypted_cache');
    for (let index = 0; index < outboxes.length; index += 1) {
      await cacheStore.put(outgoingCaches[index]!);
      await outboxStore.put(outboxes[index]!);
    }
    await tx.done;
  } catch (error) {
    throw normalizeStorageError(error);
  }
}

function normalizeTargets(senderDeviceId: string, targets: readonly EstablishedAtomicTarget[]): EstablishedAtomicTarget[] {
  if (targets.length === 0) throw new LocalStorageError('CORRUPT_STATE', 'At least one established recipient device is required');
  const devices = new Set<string>();
  const sessions = new Set<string>();
  const normalized: EstablishedAtomicTarget[] = [];
  for (const target of targets) {
    if (target.mode !== 'established') throw new LocalStorageError('CORRUPT_STATE', 'Established batch received a bootstrap target');
    if (target.recipient_device_id === senderDeviceId) throw new LocalStorageError('CORRUPT_STATE', 'Sender device cannot be its own pairwise recipient');
    if (devices.has(target.recipient_device_id)) throw new LocalStorageError('CORRUPT_STATE', `Duplicate recipient device ${target.recipient_device_id}`);
    if (sessions.has(target.session_id)) throw new LocalStorageError('CORRUPT_STATE', `Ratchet session ${target.session_id} is reused for multiple devices`);
    devices.add(target.recipient_device_id);
    sessions.add(target.session_id);
    normalized.push({ ...target });
  }
  return normalized.sort((a, b) => a.recipient_device_id.localeCompare(b.recipient_device_id));
}

function pairLock(localDeviceId: string, remoteDeviceId: string): string {
  return `crypto:${localDeviceId}:${remoteDeviceId}`;
}
