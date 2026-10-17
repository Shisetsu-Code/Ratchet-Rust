import type { IDBPDatabase } from 'idb';
import { MessageSemanticsError, validateMessageSemantics } from './content';
import { ChatSyncResponseSchema } from '../../shared/contracts/sync';
import type { CurrentSessionResponse } from '../../shared/contracts/session';
import { receiveSecureEnvelope } from '../crypto/session-establishment/receive';
import { disposeDeviceIdentity, loadDeviceIdentity } from '../crypto/key-vault/identity';
import { apiFetch } from '../transport/api';
import {
  advanceChatSyncCursor,
  cachedMessagePlaintext,
  incomingCacheKey,
  openMessageCacheRecord,
  promoteOutgoingCache,
  repairCommittedOutgoingCache,
  readChatSyncCursor,
  type CachedMessage,
} from '../storage/message-cache';
import type { LocalDbSchema } from '../storage/schema';
import { loadMessageTimelineWindow, type HistoryWindowOptions, type MessageTimelineWindow } from '../storage/message-timeline';
import { loadSendKeyContext } from '../crypto/send-context';
import type { ReceiptUpdate } from './receipt-updates';
import { scheduleDeliveredReceipts } from './receipts';

export type DisplayMessage = {
  cache_key: string;
  chat_id: string;
  revision: number;
  direction: 'INCOMING' | 'OUTGOING';
  message_id: string | null;
  client_message_id: string;
  sender_user_id: string;
  sender_device_id: string;
  sender_display_name: string | null;
  created_at: string;
  plaintext: Uint8Array;
  mutation: { target_message_id: string; type: 'EDIT' | 'TOMBSTONE' } | null;
  receipt_state: 'DELIVERED' | 'READ' | null;
  edited?: boolean;
  reply_to_message_id: string | null;
};

export type SyncChatResult = {
  revision: number; messages: DisplayMessage[]; unavailableMessageCount: number;
  receiptUpdates?: ReceiptUpdate[]; replyPreviews?: DisplayMessage[];
  history?: Omit<MessageTimelineWindow, 'messages' | 'replyPreviews'>;
  hasMore?: boolean;
};
export type SyncChatOptions = { incremental?: boolean; afterRevision?: number; history?: HistoryWindowOptions; signal?: AbortSignal };

export async function synchronizeChat(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  chatId: string,
  options: SyncChatOptions = {},
): Promise<SyncChatResult> {
  let cursor = await readChatSyncCursor(db, chatId);
  // Every tab projects the same durable cache independently of its visible
  // history page. A view watermark must never rewind network/ratchet replay.
  let hasMore = false;
  let unavailableMessageCount = 0;
  const receiptUpdates = new Map<string, 'DELIVERED' | 'READ'>();
  const senderProfiles = new Map<string, string>();
  // A realtime hint may cover a burst. Fetch enough authoritative changes in
  // one request to avoid one network round-trip per message while preserving
  // revision order during decryption and IndexedDB commits below.
  const pageLimit = 100;

  {
    options.signal?.throwIfAborted();
    const pageStartCursor = cursor;
    const response = await apiFetch(
      `/api/v1/chats/${encodeURIComponent(chatId)}/sync?after_revision=${cursor}&limit=${pageLimit}`,
      options.signal ? { signal: options.signal } : {},
      (value) => ChatSyncResponseSchema.parse(value),
    );
    if (response.chat_id !== chatId) throw new Error('Sync response chat mismatch');
    for (const profile of response.sender_profiles) senderProfiles.set(profile.sender_user_id, profile.display_name);
    let pageIdentity: Awaited<ReturnType<typeof loadDeviceIdentity>> | undefined;
    try {
      for (const change of response.changes) {
        options.signal?.throwIfAborted();
        if (change.revision <= cursor) continue;
        if (change.type === 'receipt') {
          if (change.user_id !== session.user_id) {
            await storeReceiptState(db, change.message_id, change.state);
            receiptUpdates.set(change.message_id, (await loadReceiptState(db, change.message_id))!);
          }
          await advanceChatSyncCursor(db, chatId, change.revision);
          cursor = change.revision;
          continue;
        }
        if (change.envelope) {
          const cacheKey = incomingCacheKey(change.message_id);
          const cached = await db.get('encrypted_cache', cacheKey);
          pageIdentity ??= await loadDeviceIdentity(db, session.device_id);
          if (!cached) {
            const plaintext = await receiveSecureEnvelope(db, pageIdentity.masterKey, {
              chat_id: chatId,
              local_user_id: session.user_id,
              local_device_id: session.device_id,
              remote_user_id: change.sender_user_id,
              remote_device_id: change.sender_device_id,
              header: change.envelope.header,
              ciphertext: change.envelope.ciphertext,
              delivery: {
                protocol_version: change.protocol_version,
                message_id: change.message_id,
                client_message_id: change.client_message_id,
                revision: change.revision,
                created_at: change.created_at,
                sender_display_name: change.sender_display_name,
                mutation: change.mutation,
                reply_to_message_id: change.reply_to_message_id,
              },
            });
            plaintext.fill(0);
          } else {
            try {
              const opened = await openMessageCacheRecord(pageIdentity.masterKey, cached);
              validateMessageSemantics(cachedMessagePlaintext(opened), { ...change, chat_id: chatId });
              await advanceChatSyncCursor(db, chatId, change.revision);
            } catch (error) {
              if (error instanceof MessageSemanticsError) throw error;
              // The cache is disposable; a corrupt authenticated record must
              // never let the cursor skip the authoritative server change.
              await db.delete('encrypted_cache', cacheKey);
              try {
                const plaintext = await receiveSecureEnvelope(db, pageIdentity.masterKey, {
                  chat_id: chatId,
                  local_user_id: session.user_id,
                  local_device_id: session.device_id,
                  remote_user_id: change.sender_user_id,
                  remote_device_id: change.sender_device_id,
                  header: change.envelope.header,
                  ciphertext: change.envelope.ciphertext,
                  delivery: {
                    protocol_version: change.protocol_version,
                    message_id: change.message_id,
                    client_message_id: change.client_message_id,
                    revision: change.revision,
                    created_at: change.created_at,
                    sender_display_name: change.sender_display_name,
                    mutation: change.mutation,
                    reply_to_message_id: change.reply_to_message_id,
                  },
                });
                plaintext.fill(0);
              } catch (error) {
                if (error instanceof MessageSemanticsError) throw error;
                // Old Double Ratchet keys may already be intentionally erased.
                // Isolate this one lost local history item instead of bricking
                // the whole chat forever.
                unavailableMessageCount += 1;
                await advanceChatSyncCursor(db, chatId, change.revision);
              }
            }
          }
        } else if (change.sender_device_id === session.device_id) {
          const outgoing = await db.get('encrypted_cache', `outgoing:${change.client_message_id}`);
          if (!outgoing) {
            unavailableMessageCount += 1;
            await advanceChatSyncCursor(db, chatId, change.revision);
          } else {
            await promoteOutgoingCache(db, session.device_id, chatId, change.client_message_id, change.message_id, change.revision, {
              mutation: change.mutation,
              reply_to_message_id: change.reply_to_message_id,
            });
            await advanceChatSyncCursor(db, chatId, change.revision);
          }
        } else {
          unavailableMessageCount += 1;
          await advanceChatSyncCursor(db, chatId, change.revision);
        }
        cursor = Math.max(cursor, change.revision);
      }
    } finally {
      if (pageIdentity) disposeDeviceIdentity(pageIdentity);
    }

    hasMore = response.has_more;
    if (!hasMore) {
      await advanceChatSyncCursor(db, chatId, response.revision);
      cursor = Math.max(cursor, response.revision);
    } else if (cursor <= pageStartCursor) {
      throw new Error('Sync pagination failed to advance');
    }
    // A receive turn processes one page. Realtime reconciliation continues
    // from this durable contiguous cursor until the advertised revision is met.
  }
  const history = { ...options.history, ...(options.signal ? { signal: options.signal } : {}) };
  const result = await loadChatFromEncryptedCache(db, session.device_id, chatId, cursor, history);
  result.messages = await Promise.all(result.messages.map(async (message) => ({
    ...message,
    sender_display_name: senderProfiles.get(message.sender_user_id) ?? message.sender_display_name,
    receipt_state: message.direction === 'OUTGOING' && message.message_id ? await loadReceiptState(db, message.message_id) : null,
  })));
  scheduleDeliveredReceipts(db, chatId, result.messages);
  return { ...result, hasMore, receiptUpdates: [...receiptUpdates].map(([message_id, state]) => ({ message_id, state })), unavailableMessageCount: unavailableMessageCount + result.unavailableMessageCount };
}

export function advancePaginatedSyncCursor(pageStartCursor: number, processedCursor: number, nextRevision: number): number {
  if (nextRevision <= pageStartCursor) throw new Error('Sync pagination failed to advance');
  return Math.max(processedCursor, nextRevision);
}

export async function loadChatFromEncryptedCache(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  chatId: string,
  revision = 0,
  options: HistoryWindowOptions = {},
): Promise<SyncChatResult> {
  options.signal?.throwIfAborted();
  await repairCommittedOutgoingCache(db, deviceId, chatId);
  const { masterKey } = await loadSendKeyContext(db, deviceId);
  const window = await loadMessageTimelineWindow(db, masterKey, chatId, options);
  const persistedCursor = await readChatSyncCursor(db, chatId);
  const { messages, replyPreviews, ...history } = window;
  return {
    revision: Math.max(revision, persistedCursor),
    messages: messages.map(message => ({ ...toDisplayMessage(message), edited: message.edited })),
    replyPreviews: replyPreviews.map(toDisplayMessage),
    unavailableMessageCount: 0, history,
  };
}

/**
 * SecureApp uses cache_key as its deterministic tie-break when timestamps are
 * equal. Batch commits can legitimately share created_at, so committed display
 * keys carry the authoritative D1 revision prefix. This is display-only: the
 * durable IndexedDB cache key remains unchanged.
 */
export function committedDisplayCacheKey(cacheKey: string, revision: number): string {
  if (revision <= 0) return cacheKey;
  return `revision:${revision.toString().padStart(16, '0')}:${cacheKey}`;
}

function toDisplayMessage(message: CachedMessage): DisplayMessage {
  return {
    cache_key: committedDisplayCacheKey(message.cache_key, message.revision),
    chat_id: message.chat_id,
    revision: message.revision,
    direction: message.direction,
    message_id: message.message_id,
    client_message_id: message.client_message_id,
    sender_user_id: message.sender_user_id,
    sender_device_id: message.sender_device_id,
    sender_display_name: message.sender_display_name ?? null,
    created_at: message.created_at,
    plaintext: cachedMessagePlaintext(message),
    mutation: message.mutation ?? null,
    reply_to_message_id: message.reply_to_message_id ?? null,
    receipt_state: null,
  };
}

function receiptStateKey(messageId: string): string { return `message-receipt:${messageId}`; }
export async function storeReceiptState(db: IDBPDatabase<LocalDbSchema>, messageId: string, state: 'DELIVERED' | 'READ'): Promise<void> {
  const key = receiptStateKey(messageId);
  const current = await db.get('settings', key);
  if (current?.kind === 'json' && current.value === 'READ') return;
  await db.put('settings', { key, kind: 'json', value: state });
}
export async function loadReceiptState(db: IDBPDatabase<LocalDbSchema>, messageId: string): Promise<'DELIVERED' | 'READ' | null> {
  const current = await db.get('settings', receiptStateKey(messageId));
  return current?.kind === 'json' && (current.value === 'DELIVERED' || current.value === 'READ') ? current.value : null;
}
