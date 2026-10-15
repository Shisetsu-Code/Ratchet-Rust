import type { IDBPDatabase } from 'idb';
import type { LeaseSetting, LocalDbSchema, CryptoSessionRecord } from '../../storage/schema';
import type { DeliveryCacheMetadata } from '../../storage/message-cache';
import { chatSyncCursorKey, incomingCacheKey, sealMessageCacheRecord } from '../../storage/message-cache';
import { LocalStorageError, normalizeStorageError } from '../../storage/errors';
import { assertLeaseRecord, withCryptoLock } from '../../storage/locks';
import type { PqXdhResponderPrivateBundle } from '../pqxdh/types';
import { conversationMessageAad } from '../local-state/aad';
import { base64UrlToBytes } from '../local-state/base64url';
import { assertEstablishedRatchetSession, assertRemoteIdentityPinned, disposeRatchetState, wrapRatchetCore } from '../local-state/ratchet-store';
import { wrapSkippedMessageKeys } from '../local-state/skipped-store';
import { openPrekeyMessage } from './prekey-message';
import { decodeSessionMessageHeader } from './wire';

export type CommitIncomingPrekeyMessageInput = {
  chat_id: string;
  local_user_id: string;
  local_device_id: string;
  remote_user_id: string;
  remote_device_id: string;
  header: string;
  ciphertext: string;
  responder_bundle: PqXdhResponderPrivateBundle;
  delivery?: DeliveryCacheMetadata;
};

export async function decryptAndCommitIncomingPrekeyMessage(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  input: CommitIncomingPrekeyMessageInput,
): Promise<Uint8Array> {
  const outer = decodeSessionMessageHeader(input.header);
  if (outer.kind !== 'prekey') throw new LocalStorageError('CORRUPT_STATE', 'Incoming bootstrap message is not a prekey envelope');
  const lockName = `crypto:${input.local_device_id}:${input.remote_device_id}`;
  return withCryptoLock(db, lockName, async (fence) => {
    const existingById = await db.get('sessions', outer.sessionId);
    const existingByPair = await db.getFromIndex('sessions', 'by-lock-name', lockName);
    if (existingById) {
      throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Incoming prekey session was already processed');
    }
    assertIncomingPrekeyReplacement(existingByPair, outer.sessionId, outer.pqxdh.identityPublicKey);
    const conversationAad = conversationMessageAad(input.chat_id, input.remote_user_id, input.remote_device_id, input.local_user_id, input.local_device_id);
    const opened = openPrekeyMessage({ header: input.header, ciphertext: base64UrlToBytes(input.ciphertext), responderBundle: input.responder_bundle, conversationAad });
    let plaintext: Uint8Array | undefined = opened.plaintext;
    try {
      const [wrappedCore, wrappedSkipped, cacheRecord] = await Promise.all([
        wrapRatchetCore(masterKey, { session_id: opened.sessionId, local_device_id: input.local_device_id, remote_device_id: input.remote_device_id }, opened.state),
        wrapSkippedMessageKeys(masterKey, opened.sessionId, opened.state.skipped),
        input.delivery ? sealMessageCacheRecord(masterKey, input.chat_id, incomingCacheKey(input.delivery.message_id), {
          direction: 'INCOMING',
          protocol_version: input.delivery.protocol_version,
          message_id: input.delivery.message_id,
          client_message_id: input.delivery.client_message_id,
          sender_user_id: input.remote_user_id,
          sender_device_id: input.remote_device_id,
          sender_display_name: input.delivery.sender_display_name,
          mutation: input.delivery.mutation ?? null,
          reply_to_message_id: input.delivery.reply_to_message_id ?? null,
          created_at: input.delivery.created_at,
          revision: input.delivery.revision,
        }, plaintext) : Promise.resolve(undefined),
      ]);
      const now = new Date().toISOString();
      const record: CryptoSessionRecord = {
        session_id: opened.sessionId,
        local_device_id: input.local_device_id,
        remote_device_id: input.remote_device_id,
        remote_identity_public_key: outer.pqxdh.identityPublicKey.slice(),
        lock_name: lockName,
        protocol: 'secure-messaging',
        protocol_version: 1,
        pqxdh_associated_data: opened.pqxdhAssociatedData.slice(),
        establishment_state: 'ESTABLISHED',
        state_ciphertext: wrappedCore.state_ciphertext,
        state_nonce: wrappedCore.state_nonce,
        state_version: 1,
        updated_at: now,
      };

      const tx = db.transaction(['sessions', 'skipped_message_keys', 'prekeys', 'settings', 'encrypted_cache'], 'readwrite');
      if (fence.kind === 'lease') {
        const stored = await tx.objectStore('settings').get(fence.lease_key);
        const lease = stored?.kind === 'lease' ? stored as LeaseSetting : undefined;
        assertLeaseRecord(lease, fence);
      }
      const sessions = tx.objectStore('sessions');
      if (await sessions.get(opened.sessionId)) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Incoming pairwise session appeared before commit');
      }
      const currentPair = await sessions.index('by-lock-name').get(lockName);
      if (existingByPair) {
        if (!currentPair || currentPair.session_id !== existingByPair.session_id || currentPair.state_version !== existingByPair.state_version) {
          tx.abort();
          throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Existing pairwise session changed before secure replacement');
        }
        assertEstablishedRatchetSession(currentPair);
        assertRemoteIdentityPinned(currentPair, outer.pqxdh.identityPublicKey);
        const skippedStore = tx.objectStore('skipped_message_keys');
        const oldSkipped = await skippedStore.index('by-session').getAllKeys(currentPair.session_id);
        for (const key of oldSkipped) await skippedStore.delete(key);
        await sessions.delete(currentPair.session_id);
      } else if (currentPair) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Incoming pairwise session appeared before commit');
      }
      const prekeys = tx.objectStore('prekeys');
      for (const prekeyId of [opened.usedEcOneTimePrekeyId, opened.usedPqOneTimePrekeyId]) {
        if (!prekeyId) continue;
        if (!await prekeys.get(prekeyId)) {
          tx.abort();
          throw new LocalStorageError('CORRUPT_STATE', `One-time prekey ${prekeyId} is unavailable or already consumed`);
        }
        await prekeys.delete(prekeyId);
      }
      await sessions.put(record);
      for (const skipped of wrappedSkipped) await tx.objectStore('skipped_message_keys').put(skipped);
      if (cacheRecord && input.delivery) {
        await tx.objectStore('encrypted_cache').put(cacheRecord);
        const cursorKey = chatSyncCursorKey(input.chat_id);
        const currentCursor = await tx.objectStore('settings').get(cursorKey);
        const prior = currentCursor?.kind === 'json' && Number.isSafeInteger(currentCursor.value) ? currentCursor.value as number : 0;
        if (input.delivery.revision > prior) await tx.objectStore('settings').put({ key: cursorKey, kind: 'json', value: input.delivery.revision });
      }
      await tx.done;

      if (!plaintext) throw new LocalStorageError('CORRUPT_STATE', 'Prekey decryption returned no plaintext');
      const output = plaintext;
      plaintext = undefined;
      return output;
    } catch (error) {
      throw normalizeStorageError(error);
    } finally {
      plaintext?.fill(0);
      disposeRatchetState(opened.state);
    }
  });
}

export function assertIncomingPrekeyReplacement(
  existing: CryptoSessionRecord | undefined,
  incomingSessionId: string,
  remoteIdentityPublicKey: Uint8Array,
): void {
  if (!existing) return;
  if (existing.session_id === incomingSessionId) {
    throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Incoming prekey session was already processed');
  }
  assertEstablishedRatchetSession(existing);
  assertRemoteIdentityPinned(existing, remoteIdentityPublicKey);
}
