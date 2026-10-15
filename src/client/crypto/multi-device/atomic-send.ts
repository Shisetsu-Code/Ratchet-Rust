import type { IDBPDatabase } from 'idb';
import type { DeviceEnvelope, SendMessageRequest } from '../../../shared/contracts/messages';
import type { CryptoSessionRecord, EncryptedCacheRecord, JsonSetting, LeaseSetting, LocalDbSchema, PendingOutboxRecord } from '../../storage/schema';
import { LocalStorageError, normalizeStorageError } from '../../storage/errors';
import { assertLeaseRecord, type CryptoFence, withCryptoLocks } from '../../storage/locks';
import { encryptRetryMaterial } from '../../storage/retry-material';
import { outgoingCacheKey, sealMessageCacheRecord } from '../../storage/message-cache';
import { parseSenderSequenceState, senderSequenceSettingKey } from '../../storage/sender-sequence';
import { ratchetEncrypt } from '../double-ratchet/core';
import type { DoubleRatchetState } from '../double-ratchet/types';
import { conversationMessageAad } from '../local-state/aad';
import { bytesToBase64Url } from '../local-state/base64url';
import { assertEstablishedRatchetSession, disposeRatchetState, loadRatchetState, wrapRatchetCore } from '../local-state/ratchet-store';
import { ratchetMessageToEnvelope } from '../local-state/wire';
import type { PqXdhPublicBundle, X25519KeyPair } from '../pqxdh/types';
import { sessionMessageAad } from '../session-establishment/aad';
import { initiatePrekeyMessage } from '../session-establishment/prekey-message';
import { frameAuthenticatedMessageContent } from '../../chat/content';

export type EstablishedAtomicTarget = { mode: 'established'; session_id: string; recipient_user_id: string; recipient_device_id: string };
export type BootstrapAtomicTarget = { mode: 'bootstrap'; session_id: string; recipient_user_id: string; recipient_device_id: string; bundle: PqXdhPublicBundle };
export type AtomicMultiDeviceTarget = EstablishedAtomicTarget | BootstrapAtomicTarget;
export type AtomicMultiDeviceSendInput = {
  chat_id: string; sender_user_id: string; sender_device_id: string; client_message_id: string; plaintext: Uint8Array;
  initiator_identity: X25519KeyPair | null; targets: readonly AtomicMultiDeviceTarget[];
  recovery_envelopes: SendMessageRequest['recovery_envelopes']; attachment_ids?: readonly string[]; sender_sequence?: number;
  mutation?: SendMessageRequest['mutation'];
  reply_to_message_id?: string;
  allocate_sender_sequence?: boolean;
};
type ExistingTransition = { kind: 'existing'; snapshot: CryptoSessionRecord; nextState: DoubleRatchetState; wrapped: { state_ciphertext: Uint8Array; state_nonce: Uint8Array }; envelope: DeviceEnvelope };
type BootstrapTransition = { kind: 'bootstrap'; session: CryptoSessionRecord; nextState: DoubleRatchetState; envelope: DeviceEnvelope };
type PreparedTransition = ExistingTransition | BootstrapTransition;

export async function prepareAtomicMultiDeviceMessage(db: IDBPDatabase<LocalDbSchema>, masterKey: CryptoKey, rawInput: AtomicMultiDeviceSendInput): Promise<PendingOutboxRecord> {
  const input = { ...rawInput, plaintext: frameAuthenticatedMessageContent(rawInput.plaintext, rawInput) };
  const existingOutbox = await db.get('pending_outbox', input.client_message_id);
  if (existingOutbox && existingOutbox.status !== 'NEEDS_REENCRYPT') return existingOutbox;
  const replacingRejectedCiphertext = existingOutbox?.status === 'NEEDS_REENCRYPT';
  const targets = normalizeAtomicTargets(input.sender_device_id, input.targets);
  const attachmentIds = normalizeAttachmentIds(input.attachment_ids ?? existingOutbox?.request.attachment_ids ?? []);
  const senderSequence = input.sender_sequence ?? existingOutbox?.request.sender_sequence;
  const allocateSenderSequence = input.allocate_sender_sequence === true && senderSequence === undefined;
  if (targets.some((target) => target.mode === 'bootstrap') && !input.initiator_identity) throw new LocalStorageError('CORRUPT_STATE', 'PQXDH bootstrap targets require the local device identity');
  const lockNames = targets.map((target) => pairLock(input.sender_device_id, target.recipient_device_id));
  return withCryptoLocks(db, lockNames, async (fences) => {
    const transitions: PreparedTransition[] = [];
    try {
      for (const target of targets) transitions.push(target.mode === 'established' ? await prepareExistingTransition(db, masterKey, input, target) : await prepareBootstrapTransition(db, masterKey, input, target));
      const now = new Date().toISOString();
      const pendingSessionIds = transitions.filter((t): t is BootstrapTransition => t.kind === 'bootstrap').map((t) => t.session.session_id);
      const encryptedRetryMaterial = await encryptRetryMaterial(masterKey, { chat_id: input.chat_id, sender_device_id: input.sender_device_id, client_message_id: input.client_message_id }, input.plaintext);
      const outbox: PendingOutboxRecord = {
        client_message_id: input.client_message_id,
        chat_id: input.chat_id,
        sender_device_id: input.sender_device_id,
        request: {
          client_message_id: input.client_message_id,
          ...(senderSequence !== undefined ? { sender_sequence: senderSequence } : {}),
          envelopes: transitions.map((t) => t.envelope),
          recovery_envelopes: [...input.recovery_envelopes],
          attachment_ids: attachmentIds,
          ...(input.mutation ? { mutation: input.mutation } : {}),
          ...(input.reply_to_message_id ? { reply_to_message_id: input.reply_to_message_id } : {}),
        },
        encrypted_retry_material: encryptedRetryMaterial,
        ...(pendingSessionIds.length > 0 ? { pending_session_ids: pendingSessionIds } : {}),
        status: 'PENDING',
        transport_state: 'DURABLE_LOCAL',
        attempts: existingOutbox?.attempts ?? 0,
        created_at: existingOutbox?.created_at ?? now,
        updated_at: now,
      };
      const outgoingCache = await sealMessageCacheRecord(masterKey, input.chat_id, outgoingCacheKey(input.client_message_id), {
        direction: 'OUTGOING',
        message_id: null,
        client_message_id: input.client_message_id,
        sender_user_id: input.sender_user_id,
        sender_device_id: input.sender_device_id,
        mutation: input.mutation ?? null,
        reply_to_message_id: input.reply_to_message_id ?? null,
        created_at: outbox.created_at,
        revision: 0,
      }, input.plaintext);
      await commitTransitions(
        db,
        transitions,
        fences,
        outbox,
        outgoingCache,
        replacingRejectedCiphertext,
        input.chat_id,
        input.sender_device_id,
        allocateSenderSequence,
      );
      return outbox;
    } finally {
      for (const transition of transitions) disposeRatchetState(transition.nextState);
    }
  });
}

export function normalizeAtomicTargets(senderDeviceId: string, targets: readonly AtomicMultiDeviceTarget[]): AtomicMultiDeviceTarget[] {
  if (targets.length === 0) throw new LocalStorageError('CORRUPT_STATE', 'At least one recipient device is required');
  const devices = new Set<string>();
  const sessions = new Set<string>();
  const normalized: AtomicMultiDeviceTarget[] = [];
  for (const target of targets) {
    if (target.recipient_device_id === senderDeviceId) throw new LocalStorageError('CORRUPT_STATE', 'Sender device cannot be its own pairwise recipient');
    if (devices.has(target.recipient_device_id)) throw new LocalStorageError('CORRUPT_STATE', `Duplicate recipient device ${target.recipient_device_id}`);
    if (sessions.has(target.session_id)) throw new LocalStorageError('CORRUPT_STATE', `Ratchet session ${target.session_id} is reused for multiple devices`);
    devices.add(target.recipient_device_id);
    sessions.add(target.session_id);
    normalized.push(target.mode === 'established' ? { ...target } : { ...target, bundle: target.bundle });
  }
  return normalized.sort((a, b) => a.recipient_device_id.localeCompare(b.recipient_device_id));
}

function normalizeAttachmentIds(ids: readonly string[]): string[] {
  const unique = new Set(ids);
  if (unique.size !== ids.length) throw new LocalStorageError('CORRUPT_STATE', 'Duplicate attachment ID in logical message');
  return [...ids];
}

async function prepareExistingTransition(db: IDBPDatabase<LocalDbSchema>, masterKey: CryptoKey, input: AtomicMultiDeviceSendInput, target: EstablishedAtomicTarget): Promise<ExistingTransition> {
  const snapshot = await db.get('sessions', target.session_id);
  if (!snapshot) throw new LocalStorageError('CORRUPT_STATE', `Missing ratchet session ${target.session_id}`);
  const expectedLock = pairLock(input.sender_device_id, target.recipient_device_id);
  if (snapshot.local_device_id !== input.sender_device_id || snapshot.remote_device_id !== target.recipient_device_id || snapshot.lock_name !== expectedLock) throw new LocalStorageError('CORRUPT_STATE', 'Pairwise ratchet session identity does not match target device');
  assertEstablishedRatchetSession(snapshot);
  const current = await loadRatchetState(db, masterKey, snapshot);
  let nextState: DoubleRatchetState | undefined;
  try {
    const encrypted = ratchetEncrypt(current, input.plaintext, establishedMessageAad(input, target, snapshot));
    nextState = encrypted.state;
    const transition: ExistingTransition = {
      kind: 'existing',
      snapshot,
      nextState,
      wrapped: await wrapRatchetCore(masterKey, snapshot, nextState),
      envelope: ratchetMessageToEnvelope(encrypted.message, target.recipient_user_id, target.recipient_device_id, snapshot.session_id),
    };
    nextState = undefined;
    return transition;
  } finally {
    disposeRatchetState(current);
    disposeRatchetState(nextState);
  }
}

async function prepareBootstrapTransition(db: IDBPDatabase<LocalDbSchema>, masterKey: CryptoKey, input: AtomicMultiDeviceSendInput, target: BootstrapAtomicTarget): Promise<BootstrapTransition> {
  if (!input.initiator_identity) throw new LocalStorageError('CORRUPT_STATE', 'Local identity missing for bootstrap transition');
  const lockName = pairLock(input.sender_device_id, target.recipient_device_id);
  if (await db.get('sessions', target.session_id) || await db.getFromIndex('sessions', 'by-lock-name', lockName)) throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Pairwise session appeared before PQXDH bootstrap');
  const conversationAad = conversationMessageAad(input.chat_id, input.sender_user_id, input.sender_device_id, target.recipient_user_id, target.recipient_device_id);
  const initiated = await initiatePrekeyMessage({ sessionId: target.session_id, initiatorIdentity: input.initiator_identity, recipientBundle: target.bundle, plaintext: input.plaintext, conversationAad });
  let keepState = false;
  try {
    if (initiated.state.skipped.length !== 0) throw new LocalStorageError('CORRUPT_STATE', 'Fresh initiator session unexpectedly contains skipped keys');
    const wrapped = await wrapRatchetCore(masterKey, { session_id: target.session_id, local_device_id: input.sender_device_id, remote_device_id: target.recipient_device_id }, initiated.state);
    const session: CryptoSessionRecord = {
      session_id: target.session_id,
      local_device_id: input.sender_device_id,
      remote_device_id: target.recipient_device_id,
      remote_identity_public_key: target.bundle.identityPublicKey.slice(),
      lock_name: lockName,
      protocol: 'secure-messaging',
      protocol_version: 1,
      pqxdh_associated_data: initiated.pqxdhAssociatedData.slice(),
      establishment_state: 'PENDING_FIRST_MESSAGE',
      state_ciphertext: wrapped.state_ciphertext,
      state_nonce: wrapped.state_nonce,
      state_version: 1,
      updated_at: new Date().toISOString(),
    };
    keepState = true;
    return {
      kind: 'bootstrap',
      session,
      nextState: initiated.state,
      envelope: {
        recipient_user_id: target.recipient_user_id,
        recipient_device_id: target.recipient_device_id,
        protocol: 'secure-messaging',
        protocol_version: 2,
        header: initiated.header,
        ciphertext: bytesToBase64Url(initiated.ciphertext),
      },
    };
  } finally {
    if (!keepState) disposeRatchetState(initiated.state);
  }
}

function establishedMessageAad(input: AtomicMultiDeviceSendInput, target: EstablishedAtomicTarget, session: CryptoSessionRecord): Uint8Array {
  const conversationAad = conversationMessageAad(input.chat_id, input.sender_user_id, input.sender_device_id, target.recipient_user_id, target.recipient_device_id);
  return sessionMessageAad(conversationAad, session.pqxdh_associated_data, session.session_id);
}

async function commitTransitions(
  db: IDBPDatabase<LocalDbSchema>,
  transitions: readonly PreparedTransition[],
  fences: readonly CryptoFence[],
  outbox: PendingOutboxRecord,
  outgoingCache: EncryptedCacheRecord,
  replacingRejectedCiphertext: boolean,
  chatId: string,
  senderDeviceId: string,
  allocateSenderSequence: boolean,
): Promise<void> {
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
    const currentOutbox = await tx.objectStore('pending_outbox').get(outbox.client_message_id);
    if (replacingRejectedCiphertext) {
      if (!currentOutbox || currentOutbox.status !== 'NEEDS_REENCRYPT') {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Rejected outbox changed before re-encryption commit');
      }
    } else if (currentOutbox) {
      tx.abort();
      throw new LocalStorageError('STATE_VERSION_CONFLICT', 'client_message_id already exists in local outbox');
    }

    if (allocateSenderSequence) {
      const key = senderSequenceSettingKey(chatId, senderDeviceId);
      const stored = await settings.get(key);
      const state = stored?.kind === 'json' ? parseSenderSequenceState(stored.value) : null;
      if (!state) {
        tx.abort();
        throw new LocalStorageError('CORRUPT_STATE', 'Sender sequence allocator must be seeded before atomic send');
      }
      const senderSequence = state.last_allocated + 1;
      outbox.request.sender_sequence = senderSequence;
      await settings.put({
        key,
        kind: 'json',
        value: { version: 1, last_allocated: senderSequence },
      } satisfies JsonSetting);
    }

    const sessions = tx.objectStore('sessions');
    for (const transition of transitions) {
      if (transition.kind === 'existing') {
        const current = await sessions.get(transition.snapshot.session_id);
        if (!current || current.state_version !== transition.snapshot.state_version || current.establishment_state !== 'ESTABLISHED') {
          tx.abort();
          throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Established pairwise ratchet changed before atomic commit');
        }
        await sessions.put({ ...transition.snapshot, state_ciphertext: transition.wrapped.state_ciphertext, state_nonce: transition.wrapped.state_nonce, state_version: transition.snapshot.state_version + 1, updated_at: outbox.updated_at });
      } else {
        if (await sessions.get(transition.session.session_id) || await sessions.index('by-lock-name').get(transition.session.lock_name)) {
          tx.abort();
          throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Bootstrap pairwise session appeared before atomic commit');
        }
        await sessions.put({ ...transition.session, updated_at: outbox.updated_at });
      }
    }
    await tx.objectStore('encrypted_cache').put(outgoingCache);
    await tx.objectStore('pending_outbox').put(outbox);
    await tx.done;
  } catch (error) {
    throw normalizeStorageError(error);
  }
}

function pairLock(localDeviceId: string, remoteDeviceId: string): string { return `crypto:${localDeviceId}:${remoteDeviceId}`; }
