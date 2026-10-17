import type { IDBPDatabase } from 'idb';
import { z } from 'zod';
import { bytesToBase64Url, base64UrlToBytes } from '../crypto/local-state/base64url';
import { unwrapLocalSecret, wrapLocalSecret } from '../crypto/local-state/wrapping';
import { utf8 } from '../crypto/encoding';
import { disposeDeviceIdentity, loadDeviceIdentity } from '../crypto/key-vault/identity';
import type { EncryptedCacheRecord, JsonSetting, LocalDbSchema } from './schema';
import { validateMessageSemantics } from '../chat/content';

export const CachePayloadSchema = z.object({
  version: z.literal(1),
  direction: z.enum(['INCOMING', 'OUTGOING']),
  message_id: z.string().uuid().nullable(),
  client_message_id: z.string().uuid(),
  sender_user_id: z.string().uuid(),
  sender_device_id: z.string().uuid(),
  sender_display_name: z.string().trim().min(1).max(80).nullable().optional(),
  mutation: z.object({ target_message_id: z.string().uuid(), type: z.enum(['EDIT', 'TOMBSTONE']) }).nullable().optional(),
  reply_to_message_id: z.string().uuid().nullable().optional(),
  created_at: z.string().datetime(),
  plaintext: z.string(),
});

export type DeliveryCacheMetadata = {
  protocol_version?: number | undefined;
  message_id: string;
  client_message_id: string;
  revision: number;
  created_at: string;
  sender_display_name: string | null;
  mutation?: { target_message_id: string; type: 'EDIT' | 'TOMBSTONE' } | null;
  reply_to_message_id?: string | null;
};

export type CachedMessage = z.infer<typeof CachePayloadSchema> & {
  cache_key: string;
  chat_id: string;
  revision: number;
};

// The raw cache is an event journal, never an unbounded plaintext view.
export const CACHE_PAGE_MESSAGES = 80;
export const CACHE_PAGE_BYTES = 2 * 1024 * 1024;

export type CacheMessageMetadata = {
  protocol_version?: number | undefined;
  direction: 'INCOMING' | 'OUTGOING';
  message_id?: string | null;
  client_message_id: string;
  sender_user_id: string;
  sender_device_id: string;
  sender_display_name?: string | null;
  mutation?: { target_message_id: string; type: 'EDIT' | 'TOMBSTONE' } | null;
  reply_to_message_id?: string | null;
  created_at: string;
  revision: number;
};

export type MessageOrderable = {
  revision: number;
  created_at: string;
  cache_key: string;
};

export function incomingCacheKey(messageId: string): string { return `message:${messageId}`; }
export function outgoingCacheKey(clientMessageId: string): string { return `outgoing:${clientMessageId}`; }
export function chatSyncCursorKey(chatId: string): string { return `sync:${chatId}`; }
export function chatTimelineCursorKey(chatId: string): string { return `timeline-projection:${chatId}`; }

/**
 * D1 revision is the canonical order for committed chat events. Server-side
 * batch commits intentionally share an acceptance timestamp, so created_at is
 * not a safe ordering key for two committed messages. Pending local messages
 * do not yet have a D1 revision and retain chronological local ordering.
 */
export function compareMessageOrder(a: MessageOrderable, b: MessageOrderable): number {
  if (a.revision > 0 && b.revision > 0) {
    const byRevision = a.revision - b.revision;
    if (byRevision !== 0) return byRevision;
  }
  return a.created_at.localeCompare(b.created_at) || a.cache_key.localeCompare(b.cache_key);
}

export async function sealMessageCacheRecord(
  masterKey: CryptoKey,
  chatId: string,
  cacheKey: string,
  metadata: CacheMessageMetadata,
  plaintext: Uint8Array,
): Promise<EncryptedCacheRecord> {
  const semantics = validateMessageSemantics(plaintext, { ...metadata, chat_id: chatId });
  const payload = utf8(JSON.stringify({
    version: 1,
    direction: metadata.direction,
    message_id: metadata.message_id ?? null,
    client_message_id: metadata.client_message_id,
    sender_user_id: metadata.sender_user_id,
    sender_device_id: metadata.sender_device_id,
    sender_display_name: metadata.sender_display_name ?? null,
    mutation: semantics.mutation,
    reply_to_message_id: semantics.reply_to_message_id,
    created_at: metadata.created_at,
    plaintext: bytesToBase64Url(plaintext),
  }));
  try {
    const wrapped = await wrapLocalSecret(masterKey, payload, cacheAad(chatId, cacheKey));
    return {
      cache_key: cacheKey,
      chat_id: chatId,
      revision: metadata.revision,
      ciphertext: wrapped.ciphertext,
      nonce: wrapped.nonce,
      updated_at: new Date().toISOString(),
    };
  } finally {
    payload.fill(0);
  }
}

export async function openMessageCacheRecord(masterKey: CryptoKey, record: EncryptedCacheRecord): Promise<CachedMessage> {
  const plaintext = await unwrapLocalSecret(masterKey, { nonce: record.nonce, ciphertext: record.ciphertext }, cacheAad(record.chat_id, record.cache_key));
  try {
    const parsed = CachePayloadSchema.parse(JSON.parse(new TextDecoder().decode(plaintext)) as unknown);
    const semantics = validateMessageSemantics(base64UrlToBytes(parsed.plaintext), { ...parsed, chat_id: record.chat_id });
    return { ...parsed, ...semantics, cache_key: record.cache_key, chat_id: record.chat_id, revision: record.revision };
  } finally {
    plaintext.fill(0);
  }
}

export async function loadCachedMessages(db: IDBPDatabase<LocalDbSchema>, masterKey: CryptoKey, chatId: string): Promise<CachedMessage[]> {
  const records = await readCacheRevisionWindow(db, chatId, 0, Number.MAX_SAFE_INTEGER, 'prev');
  const opened: CachedMessage[] = [];
  for (const record of records) opened.push(await openMessageCacheRecord(masterKey, record));
  return opened.sort(compareMessageOrder);
}

export type ResilientCachedMessages = {
  messages: CachedMessage[];
  corruptRecordCount: number;
  earliestCorruptRevision: number | null;
};

export async function loadCachedMessagesResilient(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  chatId: string,
): Promise<ResilientCachedMessages> {
  return loadCachedMessageRangeResilient(db, masterKey, chatId, 0, Number.MAX_SAFE_INTEGER, 'prev');
}

export async function loadCachedMessagesAfterRevisionResilient(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  chatId: string,
  afterRevision: number,
  throughRevision: number,
): Promise<ResilientCachedMessages> {
  if (!Number.isSafeInteger(afterRevision) || !Number.isSafeInteger(throughRevision) || afterRevision < 0 || throughRevision < afterRevision) {
    throw new Error('Invalid encrypted cache revision window');
  }
  return loadCachedMessageRangeResilient(db, masterKey, chatId, afterRevision, throughRevision);
}

async function loadCachedMessageRangeResilient(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  chatId: string,
  afterRevision: number,
  throughRevision: number,
  direction: IDBCursorDirection = 'next',
): Promise<ResilientCachedMessages> {
  const records = await readCacheRevisionWindow(db, chatId, afterRevision, throughRevision, direction);
  const messages: CachedMessage[] = [];
  let corruptRecordCount = 0;
  let earliestCorruptRevision: number | null = null;
  for (const record of records) {
    try {
      messages.push(await openMessageCacheRecord(masterKey, record));
    } catch {
      corruptRecordCount += 1;
      earliestCorruptRevision = earliestCorruptRevision === null
        ? record.revision
        : Math.min(earliestCorruptRevision, record.revision);
      await db.delete('encrypted_cache', record.cache_key);
    }
  }
  return { messages: messages.sort(compareMessageOrder), corruptRecordCount, earliestCorruptRevision };
}

export async function repairCommittedOutgoingCache(db: IDBPDatabase<LocalDbSchema>, deviceId: string, chatId: string): Promise<void> {
  // Only unpromoted local cache entries can need ACK repair. Historical
  // COMMITTED outbox rows must not be loaded on every view refresh.
  const pending = await db.getAllFromIndex('encrypted_cache', 'by-chat-revision', IDBKeyRange.only([chatId, 0]), CACHE_PAGE_MESSAGES);
  for (const cached of pending) {
    if (!cached.cache_key.startsWith('outgoing:')) continue;
    const record = await db.get('pending_outbox', cached.cache_key.slice('outgoing:'.length));
    if (!record) continue;
    if (record.status !== 'COMMITTED' || !record.server_message_id || record.server_revision === undefined) continue;
    // The encrypted-cache revision is visible metadata. Avoid opening and
    // resealing every historical COMMITTED message on every chat load.
    if (cached.chat_id !== chatId || cached.revision >= record.server_revision) continue;
    await promoteOutgoingCache(db, deviceId, chatId, record.client_message_id, record.server_message_id, record.server_revision, {
      mutation: record.request.mutation ?? null,
      reply_to_message_id: record.request.reply_to_message_id ?? null,
    });
  }
}

export async function readCacheRevisionWindow(db: IDBPDatabase<LocalDbSchema>, chatId: string, afterRevision: number, throughRevision: number, direction: IDBCursorDirection = 'next', limit = CACHE_PAGE_MESSAGES): Promise<EncryptedCacheRecord[]> {
  if (!Number.isSafeInteger(afterRevision) || !Number.isSafeInteger(throughRevision) || afterRevision < 0 || throughRevision < afterRevision) {
    throw new Error('Invalid encrypted cache revision window');
  }
  if (afterRevision === throughRevision) return [];
  const tx = db.transaction('encrypted_cache', 'readonly');
  const index = tx.store.index('by-chat-revision');
  let cursor = await index.openCursor(IDBKeyRange.bound([chatId, afterRevision], [chatId, throughRevision], true, false), direction);
  const records: EncryptedCacheRecord[] = [];
  let bytes = 0;
  while (cursor && records.length < Math.min(limit, CACHE_PAGE_MESSAGES)) {
    const record = cursor.value;
    if (records.length && bytes + record.ciphertext.byteLength > CACHE_PAGE_BYTES) break;
    records.push(record);
    bytes += record.ciphertext.byteLength;
    cursor = await cursor.continue();
  }
  await tx.done;
  return records;
}

export async function loadCachedMessagesAfterRevision(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  chatId: string,
  afterRevision: number,
  throughRevision: number,
): Promise<CachedMessage[]> {
  if (!Number.isSafeInteger(afterRevision) || !Number.isSafeInteger(throughRevision) || afterRevision < 0 || throughRevision < afterRevision) {
    throw new Error('Invalid encrypted cache revision window');
  }
  const records = await readCacheRevisionWindow(db, chatId, afterRevision, throughRevision);
  const opened: CachedMessage[] = [];
  for (const record of records) opened.push(await openMessageCacheRecord(masterKey, record));
  return opened.sort(compareMessageOrder);
}

export function cachedMessagePlaintext(message: CachedMessage): Uint8Array { return base64UrlToBytes(message.plaintext); }

export async function readChatSyncCursor(db: IDBPDatabase<LocalDbSchema>, chatId: string): Promise<number> {
  const setting = await db.get('settings', chatSyncCursorKey(chatId));
  if (!setting || setting.kind !== 'json' || !Number.isSafeInteger(setting.value) || (setting.value as number) < 0) return 0;
  return setting.value as number;
}

export async function advanceChatSyncCursor(db: IDBPDatabase<LocalDbSchema>, chatId: string, revision: number): Promise<void> {
  if (!Number.isSafeInteger(revision) || revision < 0) throw new Error('Invalid chat sync revision');
  const key = chatSyncCursorKey(chatId);
  const tx = db.transaction('settings', 'readwrite');
  const current = await tx.store.get(key);
  const prior = current?.kind === 'json' && Number.isSafeInteger(current.value) ? current.value as number : 0;
  if (revision > prior) await tx.store.put({ key, kind: 'json', value: revision } satisfies JsonSetting);
  await tx.done;
}

export async function rewindChatSyncCursorForCacheRecovery(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  revision: number,
): Promise<void> {
  if (!Number.isSafeInteger(revision) || revision < 0) throw new Error('Invalid chat sync recovery revision');
  const key = chatSyncCursorKey(chatId);
  const tx = db.transaction('settings', 'readwrite');
  const current = await tx.store.get(key);
  const prior = current?.kind === 'json' && Number.isSafeInteger(current.value) ? current.value as number : 0;
  if (revision < prior) await tx.store.put({ key, kind: 'json', value: revision } satisfies JsonSetting);
  await tx.done;
}

export async function promoteOutgoingCache(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  chatId: string,
  clientMessageId: string,
  messageId: string,
  revision: number,
  metadata?: Pick<DeliveryCacheMetadata, 'mutation' | 'reply_to_message_id'>,
): Promise<void> {
  const key = outgoingCacheKey(clientMessageId);
  const record = await db.get('encrypted_cache', key);
  if (!record || record.chat_id !== chatId) return;
  const identity = await loadDeviceIdentity(db, deviceId);
  let plaintext: Uint8Array | undefined;
  try {
    const cached = await openMessageCacheRecord(identity.masterKey, record);
    // undefined means "metadata not supplied"; null is an authoritative
    // absence and must be able to clear stale legacy cache metadata.
    const mutation = metadata && Object.hasOwn(metadata, 'mutation')
      ? metadata.mutation ?? null
      : cached.mutation ?? null;
    const replyToMessageId = metadata && Object.hasOwn(metadata, 'reply_to_message_id')
      ? metadata.reply_to_message_id ?? null
      : cached.reply_to_message_id ?? null;
    const mutationMatches = cached.mutation?.target_message_id === mutation?.target_message_id
      && cached.mutation?.type === mutation?.type;
    if (cached.message_id === messageId
      && mutationMatches
      && (cached.reply_to_message_id ?? null) === replyToMessageId
      && record.revision >= revision) return;
    plaintext = cachedMessagePlaintext(cached);
    const promoted = await sealMessageCacheRecord(identity.masterKey, chatId, key, {
      direction: cached.direction,
      message_id: messageId,
      client_message_id: cached.client_message_id,
      sender_user_id: cached.sender_user_id,
      sender_device_id: cached.sender_device_id,
      sender_display_name: cached.sender_display_name ?? null,
      mutation,
      reply_to_message_id: replyToMessageId,
      created_at: cached.created_at,
      revision: Math.max(revision, record.revision),
    }, plaintext);
    // An ACK proves only that this message has a server revision. It does not
    // prove that every earlier chat revision has been processed contiguously.
    // Only the ordered /sync or realtime reconciliation paths may advance the
    // chat cursor.
    const tx = db.transaction(['encrypted_cache', 'settings'], 'readwrite');
    await tx.objectStore('encrypted_cache').put(promoted);
    await invalidateTimelineProjectionInTransaction(tx.objectStore('settings'), chatId, promoted.revision);
    await tx.done;
  } finally {
    plaintext?.fill(0);
    disposeDeviceIdentity(identity);
  }
}

export async function putCursorInTransaction(
  settings: { get(key: string): Promise<unknown>; put(value: JsonSetting): Promise<unknown> },
  chatId: string,
  revision: number,
): Promise<void> {
  const key = chatSyncCursorKey(chatId);
  const current = await settings.get(key) as { kind?: string; value?: unknown } | undefined;
  const prior = current?.kind === 'json' && Number.isSafeInteger(current.value) ? current.value as number : 0;
  if (revision > prior) await settings.put({ key, kind: 'json', value: revision });
  await invalidateTimelineProjectionInTransaction(settings, chatId, revision);
}

async function invalidateTimelineProjectionInTransaction(
  settings: { get(key: string): Promise<unknown>; put(value: JsonSetting): Promise<unknown> },
  chatId: string, revision: number,
): Promise<void> {
  const key = chatTimelineCursorKey(chatId);
  const projection = await settings.get(key) as { kind?: string; value?: unknown } | undefined;
  if (revision > 0 && projection?.kind === 'json' && typeof projection.value === 'number' && projection.value >= revision) {
    await settings.put({ key, kind: 'json', value: revision - 1 });
  }
}

function cacheAad(chatId: string, cacheKey: string): Uint8Array {
  return utf8(`RatchetSecureSupport/message-cache/v1\u0000${chatId}\u0000${cacheKey}`);
}
