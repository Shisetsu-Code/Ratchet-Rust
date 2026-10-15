import type { IDBPDatabase } from 'idb';
import type { CurrentSessionResponse } from '../../shared/contracts/session';
import type { RealtimeCommittedMessage } from '../../shared/contracts/realtime';
import { loadSendKeyContext as loadLocalKeyContext } from '../crypto/send-context';
import { receiveSecureEnvelope } from '../crypto/session-establishment/receive';
import {
  advanceChatSyncCursor,
  cachedMessagePlaintext,
  incomingCacheKey,
  openMessageCacheRecord,
} from '../storage/message-cache';
import type { LocalDbSchema } from '../storage/schema';
import { committedDisplayCacheKey, type DisplayMessage } from './sync';
import { validateMessageSemantics } from './content';

/**
 * Apply one contiguous, already-D1-committed realtime message. The same receive
 * primitive used by HTTP reconciliation performs ratchet advancement, local
 * encrypted-cache persistence and cursor advancement atomically.
 */
export async function applyRealtimeCommittedMessage(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  event: RealtimeCommittedMessage,
): Promise<DisplayMessage> {
  if (event.envelope.recipient_user_id !== session.user_id
    || event.envelope.recipient_device_id !== session.device_id) {
    throw new Error('Realtime envelope recipient does not match current authenticated device');
  }

  const senderDisplayName = event.sender_display_name ?? null;
  const cacheKey = incomingCacheKey(event.message_id);
  // Established receive and cache access need only the non-extractable local
  // wrapping key. PQXDH loads/verifies the private identity inside its own path.
  const identity = await loadLocalKeyContext(db, session.device_id);
    const existing = await db.get('encrypted_cache', cacheKey);
    if (existing) {
      if (existing.chat_id !== event.chat_id) throw new Error('Realtime cached message belongs to another chat');
      const cached = await openMessageCacheRecord(identity.masterKey, existing);
      const semantics = validateMessageSemantics(cachedMessagePlaintext(cached), { ...event, protocol_version: event.envelope.protocol_version });
      await advanceChatSyncCursor(db, event.chat_id, event.revision);
      return {
        cache_key: committedDisplayCacheKey(cached.cache_key, event.revision),
        chat_id: cached.chat_id,
        revision: event.revision,
        direction: cached.direction,
        message_id: cached.message_id,
        client_message_id: cached.client_message_id,
        sender_user_id: cached.sender_user_id,
        sender_device_id: cached.sender_device_id,
        sender_display_name: senderDisplayName ?? cached.sender_display_name ?? null,
        mutation: semantics.mutation,
        receipt_state: null,
        reply_to_message_id: semantics.reply_to_message_id,
        created_at: cached.created_at,
        plaintext: cachedMessagePlaintext(cached),
      };
    }

    const plaintext = await receiveSecureEnvelope(db, identity.masterKey, {
      chat_id: event.chat_id,
      local_user_id: session.user_id,
      local_device_id: session.device_id,
      remote_user_id: event.sender_user_id,
      remote_device_id: event.sender_device_id,
      header: event.envelope.header,
      ciphertext: event.envelope.ciphertext,
      delivery: {
        protocol_version: event.envelope.protocol_version,
        message_id: event.message_id,
        client_message_id: event.client_message_id,
        revision: event.revision,
        created_at: event.accepted_at,
        sender_display_name: senderDisplayName,
        mutation: event.mutation,
        reply_to_message_id: event.reply_to_message_id,
      },
    });

    const semantics = validateMessageSemantics(plaintext, { ...event, protocol_version: event.envelope.protocol_version });
    return {
      cache_key: committedDisplayCacheKey(cacheKey, event.revision),
      chat_id: event.chat_id,
      revision: event.revision,
      direction: event.sender_user_id === session.user_id ? 'OUTGOING' : 'INCOMING',
      message_id: event.message_id,
      client_message_id: event.client_message_id,
      sender_user_id: event.sender_user_id,
      sender_device_id: event.sender_device_id,
      sender_display_name: senderDisplayName,
      mutation: semantics.mutation,
      receipt_state: null,
      reply_to_message_id: semantics.reply_to_message_id,
      created_at: event.accepted_at,
      plaintext,
    };
}
