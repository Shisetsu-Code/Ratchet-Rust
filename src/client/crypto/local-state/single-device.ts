import { validateMessageSemantics } from '../../chat/content';
import type { IDBPDatabase } from 'idb';
import type { PendingOutboxRecord, LeaseSetting, LocalDbSchema } from '../../storage/schema';
import type { DeliveryCacheMetadata } from '../../storage/message-cache';
import { cachedMessagePlaintext, openMessageCacheRecord, chatSyncCursorKey, incomingCacheKey, sealMessageCacheRecord } from '../../storage/message-cache';
import { LocalStorageError, normalizeStorageError } from '../../storage/errors';
import { assertLeaseRecord, withCryptoLock } from '../../storage/locks';
import { prepareEncryptedOutboxMessage } from '../../storage/crypto-transition';
import { ratchetDecrypt, ratchetEncrypt } from '../double-ratchet/core';
import type { DoubleRatchetState } from '../double-ratchet/types';
import { assertEstablishedRatchetSession, disposeRatchetState, loadRatchetState, wrapRatchetCore } from './ratchet-store';
import { conversationMessageAad } from './aad';
import { envelopeToRatchetMessage, ratchetMessageToEnvelope } from './wire';
import { wrapSkippedMessageKeys } from './skipped-store';
import { sessionMessageAad } from '../session-establishment/aad';

export type SingleDeviceSendInput = {
  session_id: string;
  chat_id: string;
  sender_user_id: string;
  sender_device_id: string;
  recipient_user_id: string;
  recipient_device_id: string;
  client_message_id: string;
  plaintext: Uint8Array;
};

export type SingleDeviceDecryptInput = {
  session_id: string;
  chat_id: string;
  local_user_id: string;
  local_device_id: string;
  remote_user_id: string;
  remote_device_id: string;
  header: string;
  ciphertext: string;
  delivery?: DeliveryCacheMetadata;
};

export async function prepareSingleDeviceRatchetMessage(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  input: SingleDeviceSendInput,
): Promise<PendingOutboxRecord> {
  if (input.sender_device_id === input.recipient_device_id) throw new LocalStorageError('CORRUPT_STATE', 'Sender and recipient device IDs must differ');
  return prepareEncryptedOutboxMessage(
    db,
    {
      session_id: input.session_id,
      local_device_id: input.sender_device_id,
      remote_device_id: input.recipient_device_id,
      chat_id: input.chat_id,
      client_message_id: input.client_message_id,
      sender_device_id: input.sender_device_id,
    },
    async (current) => {
      if (!current) throw new LocalStorageError('CORRUPT_STATE', 'Established ratchet session is missing');
      assertEstablishedRatchetSession(current);
      let state: DoubleRatchetState | undefined;
      let nextState: DoubleRatchetState | undefined;
      try {
        state = await loadRatchetState(db, masterKey, current);
        const conversationAad = conversationMessageAad(input.chat_id, input.sender_user_id, input.sender_device_id, input.recipient_user_id, input.recipient_device_id);
        const aad = sessionMessageAad(conversationAad, current.pqxdh_associated_data, current.session_id);
        const encrypted = ratchetEncrypt(state, input.plaintext, aad);
        nextState = encrypted.state;
        const wrapped = await wrapRatchetCore(masterKey, current, nextState);
        const envelope = ratchetMessageToEnvelope(encrypted.message, input.recipient_user_id, input.recipient_device_id, current.session_id);
        return {
          next_session: {
            session_id: current.session_id,
            local_device_id: current.local_device_id,
            remote_device_id: current.remote_device_id,
            remote_identity_public_key: current.remote_identity_public_key,
            lock_name: current.lock_name,
            protocol: current.protocol,
            protocol_version: current.protocol_version,
            pqxdh_associated_data: current.pqxdh_associated_data,
            establishment_state: current.establishment_state,
            state_ciphertext: wrapped.state_ciphertext,
            state_nonce: wrapped.state_nonce,
          },
          request: { client_message_id: input.client_message_id, envelopes: [envelope], recovery_envelopes: [], attachment_ids: [] },
        };
      } finally {
        disposeRatchetState(state);
        disposeRatchetState(nextState);
      }
    },
  );
}

export async function decryptAndCommitSingleDeviceRatchetMessage(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  input: SingleDeviceDecryptInput,
): Promise<Uint8Array> {
  if (input.local_device_id === input.remote_device_id) throw new LocalStorageError('CORRUPT_STATE', 'Local and remote device IDs must differ');
  const lockName = `crypto:${input.local_device_id}:${input.remote_device_id}`;
  return withCryptoLock(db, lockName, async (fence) => {
    const snapshot = await db.get('sessions', input.session_id);
    if (!snapshot) throw new LocalStorageError('CORRUPT_STATE', 'Established ratchet session is missing');
    if (snapshot.local_device_id !== input.local_device_id || snapshot.remote_device_id !== input.remote_device_id || snapshot.lock_name !== lockName) {
      throw new LocalStorageError('CORRUPT_STATE', 'Stored ratchet session identity does not match the incoming envelope');
    }
    assertEstablishedRatchetSession(snapshot);
    // HTTP and WebSocket can both observe an absent cache before acquiring
    // this lock. Recheck here: the first transport may have consumed the key.
    if (input.delivery) {
      const cached = await db.get('encrypted_cache', incomingCacheKey(input.delivery.message_id));
      if (cached) {
        if (cached.chat_id !== input.chat_id) throw new LocalStorageError('CORRUPT_STATE', 'Cached delivery belongs to another chat');
        const opened = await openMessageCacheRecord(masterKey, cached);
        const plaintext = cachedMessagePlaintext(opened);
        try {
          validateMessageSemantics(plaintext, { ...input.delivery, chat_id: input.chat_id,
            sender_user_id: input.remote_user_id, sender_device_id: input.remote_device_id });
          return plaintext;
        } catch (error) { plaintext.fill(0); throw error; }
      }
    }

    let state: DoubleRatchetState | undefined;
    let nextState: DoubleRatchetState | undefined;
    let plaintext: Uint8Array | undefined;
    try {
      state = await loadRatchetState(db, masterKey, snapshot);
      const message = envelopeToRatchetMessage(input.header, input.ciphertext, snapshot.session_id);
      const conversationAad = conversationMessageAad(input.chat_id, input.remote_user_id, input.remote_device_id, input.local_user_id, input.local_device_id);
      const aad = sessionMessageAad(conversationAad, snapshot.pqxdh_associated_data, snapshot.session_id);
      const decrypted = ratchetDecrypt(state, message, aad);
      nextState = decrypted.state;
      plaintext = decrypted.plaintext;

      const [wrappedCore, wrappedSkipped, cacheRecord] = await Promise.all([
        wrapRatchetCore(masterKey, snapshot, nextState),
        wrapSkippedMessageKeys(masterKey, snapshot.session_id, nextState.skipped),
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
      const nextRecord = { ...snapshot, state_ciphertext: wrappedCore.state_ciphertext, state_nonce: wrappedCore.state_nonce, state_version: snapshot.state_version + 1, updated_at: now };

      try {
        const tx = db.transaction(['sessions', 'skipped_message_keys', 'settings', 'encrypted_cache'], 'readwrite');
        if (fence.kind === 'lease') {
          const storedFence = await tx.objectStore('settings').get(fence.lease_key);
          const lease = storedFence?.kind === 'lease' ? storedFence as LeaseSetting : undefined;
          assertLeaseRecord(lease, fence);
        }
        const current = await tx.objectStore('sessions').get(input.session_id);
        if (!current || current.state_version !== snapshot.state_version) {
          tx.abort();
          throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Ratchet state changed before decrypt commit');
        }

        const skippedStore = tx.objectStore('skipped_message_keys');
        const existing = await skippedStore.index('by-session').getAllKeys(input.session_id);
        for (const key of existing) await skippedStore.delete(key);
        for (const record of wrappedSkipped) await skippedStore.put(record);
        await tx.objectStore('sessions').put(nextRecord);
        if (cacheRecord && input.delivery) {
          await tx.objectStore('encrypted_cache').put(cacheRecord);
          const cursorKey = chatSyncCursorKey(input.chat_id);
          const currentCursor = await tx.objectStore('settings').get(cursorKey);
          const prior = currentCursor?.kind === 'json' && Number.isSafeInteger(currentCursor.value) ? currentCursor.value as number : 0;
          if (input.delivery.revision > prior) await tx.objectStore('settings').put({ key: cursorKey, kind: 'json', value: input.delivery.revision });
        }
        await tx.done;
      } catch (error) {
        throw normalizeStorageError(error);
      }

      if (!plaintext) throw new LocalStorageError('CORRUPT_STATE', 'Decryption returned no plaintext');
      const output = plaintext;
      plaintext = undefined;
      return output;
    } finally {
      plaintext?.fill(0);
      disposeRatchetState(state);
      disposeRatchetState(nextState);
    }
  });
}
