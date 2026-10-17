import type { IDBPDatabase } from 'idb';
import { z } from 'zod';
import { decodeMessageContent, encodeMessageContent } from '../chat/content';
import { bytesToBase64Url } from '../crypto/local-state/base64url';
import { unwrapLocalSecret, wrapLocalSecret } from '../crypto/local-state/wrapping';
import { assertLeaseRecord, withCryptoLock } from './locks';
import { LocalStorageError } from './errors';
import {
  CachePayloadSchema, CACHE_PAGE_BYTES, CACHE_PAGE_MESSAGES,
  cachedMessagePlaintext, openMessageCacheRecord, readCacheRevisionWindow,
  readChatSyncCursor, chatTimelineCursorKey as projectionKey, rewindChatSyncCursorForCacheRecovery, type CachedMessage,
} from './message-cache';
import type { EncryptedTimelineRecord, LocalDbSchema } from './schema';

export const HISTORY_PROJECTION_BATCH = 32;
export const HISTORY_WINDOW_MESSAGES = CACHE_PAGE_MESSAGES;
export const HISTORY_WINDOW_BYTES = CACHE_PAGE_BYTES;

const TimelineMessageSchema = CachePayloadSchema.extend({
  cache_key: z.string(), chat_id: z.string().uuid(), revision: z.number().int().positive(),
  edited: z.boolean(),
});
const ProjectionSchema = z.object({
  version: z.literal(1), message: TimelineMessageSchema.nullable(),
  pending_edit: z.string().nullable(), deleted: z.boolean(),
});
type Projection = z.infer<typeof ProjectionSchema>;
export type TimelineMessage = z.infer<typeof TimelineMessageSchema>;
export type HistoryWindowOptions = { beforeRevision?: number; afterRevision?: number; signal?: AbortSignal };
export type MessageTimelineWindow = {
  messages: TimelineMessage[];
  replyPreviews: TimelineMessage[];
  oldestRevision: number | null;
  newestRevision: number | null;
  hasOlder: boolean;
  hasNewer: boolean;
};

function timelineKey(chatId: string, messageId: string) { return `${chatId}:${messageId}`; }
function rebuildKey(chatId: string) { return `timeline-rebuild:${chatId}`; }
function aad(record: Omit<EncryptedTimelineRecord, 'ciphertext' | 'nonce'>) {
  return new TextEncoder().encode(JSON.stringify(['message-timeline-v1', record.timeline_key, record.chat_id, record.revision, record.applied_revision, record.visible]));
}

class CorruptTimelineRecord extends Error {
  constructor(readonly record: EncryptedTimelineRecord, cause: unknown) {
    super('Derived message history could not be authenticated', { cause });
  }
}

async function openProjection(key: CryptoKey, record: EncryptedTimelineRecord): Promise<Projection> {
  let plaintext: Uint8Array | undefined;
  try {
    if (record.ciphertext.byteLength > HISTORY_WINDOW_BYTES) throw new Error('Encrypted timeline record is too large');
    plaintext = await unwrapLocalSecret(key, record, aad(record));
    return ProjectionSchema.parse(JSON.parse(new TextDecoder().decode(plaintext)));
  } catch (error) { throw new CorruptTimelineRecord(record, error); }
  finally { plaintext?.fill(0); }
}

async function sealProjection(key: CryptoKey, metadata: Omit<EncryptedTimelineRecord, 'ciphertext' | 'nonce'>, projection: Projection): Promise<EncryptedTimelineRecord> {
  const plaintext = new TextEncoder().encode(JSON.stringify(projection));
  try { return { ...metadata, ...await wrapLocalSecret(key, plaintext, aad(metadata)) }; }
  finally { plaintext.fill(0); }
}

/**
 * Materialize a bounded part of the authenticated local event journal. The
 * projection's watermark is deliberately separate from the receive cursor:
 * paging never claims that an unprocessed network/ratchet event was received.
 * Target state survives window eviction, so a later page cannot resurrect a
 * tombstone or forget an edit whose event was outside that page.
 */
export async function projectChatHistoryBatch(
  db: IDBPDatabase<LocalDbSchema>, key: CryptoKey, chatId: string,
  throughRevision: number, signal?: AbortSignal,
): Promise<{ processed: number; revision: number; complete: boolean }> {
  try {
    return await withCryptoLock(db, `timeline:${chatId}`, async fence => {
      signal?.throwIfAborted();
      const rebuild = await db.get('settings', rebuildKey(chatId));
      if (rebuild?.kind === 'json' && rebuild.value === true) {
        // Delete only derived keys, a bounded batch at a time. Keeping the
        // durable marker until deletion finishes makes cancellation resumable.
        const tx = db.transaction(['message_timeline', 'settings'], 'readwrite');
        if (fence.kind === 'lease') {
          const held = await tx.objectStore('settings').get(fence.lease_key);
          assertLeaseRecord(held?.kind === 'lease' ? held : undefined, fence);
        }
        const store = tx.objectStore('message_timeline');
        let cursor = await store.openKeyCursor(IDBKeyRange.bound(`${chatId}:`, `${chatId}:\uffff`));
        let removed = 0;
        while (cursor && removed < HISTORY_PROJECTION_BATCH) {
          await store.delete(cursor.primaryKey);
          removed++;
          cursor = await cursor.continue();
        }
        if (!cursor) await tx.objectStore('settings').delete(rebuildKey(chatId));
        await tx.done;
        return { processed: removed, revision: 0, complete: false };
      }
      const setting = await db.get('settings', projectionKey(chatId));
      const after = setting?.kind === 'json' && Number.isSafeInteger(setting.value) ? setting.value as number : 0;
      const through = Math.min(throughRevision, await readChatSyncCursor(db, chatId));
      if (after >= through) return { processed: 0, revision: after, complete: true };
      const records = await readCacheRevisionWindow(db, chatId, after, through, 'next', HISTORY_PROJECTION_BATCH);
      const updates = new Map<string, { row: EncryptedTimelineRecord; projection: Projection }>();
      const versions = new Map<string, number | undefined>();
      let last = after;
      for (const record of records) {
        signal?.throwIfAborted();
        let event: CachedMessage;
        try { event = await openMessageCacheRecord(key, record); }
        catch (error) {
          await db.delete('encrypted_cache', record.cache_key);
          await rewindChatSyncCursorForCacheRecovery(db, chatId, Math.max(0, record.revision - 1));
          throw error;
        }
        last = Math.max(last, record.revision);
        const id = event.mutation?.target_message_id ?? event.message_id;
        if (!id) continue;
        const idKey = timelineKey(chatId, id);
        const pending = updates.get(idKey);
        const old = pending?.row ?? await db.get('message_timeline', idKey);
        if (!versions.has(idKey)) versions.set(idKey, old?.applied_revision);
        const projection = pending?.projection ?? (old ? await openProjection(key, old) : { version: 1, message: null, pending_edit: null, deleted: false } satisfies Projection);
        // A late ACK can recover an original whose later EDIT was already
        // projected. Restore its identity/order while keeping that newer edit.
        if (old && old.applied_revision >= event.revision
          && (event.mutation || projection.message || projection.deleted)) continue;
        if (event.mutation?.type === 'TOMBSTONE') {
          projection.deleted = true;
          projection.message = null;
          projection.pending_edit = null;
        } else if (event.mutation?.type === 'EDIT') {
          if (!projection.deleted) {
            if (projection.message) projection.message = { ...projection.message, plaintext: event.plaintext, edited: true };
            else projection.pending_edit = event.plaintext;
          }
        } else if (!projection.deleted) {
          // A duplicate original (e.g. ACK cache promotion plus receive) cannot
          // overwrite content already derived from a later authenticated edit.
          projection.message ??= { ...event, mutation: null, plaintext: projection.pending_edit ?? event.plaintext, edited: projection.pending_edit !== null };
          projection.pending_edit = null;
        }
        const row = await sealProjection(key, {
          timeline_key: idKey, chat_id: chatId,
          revision: projection.message?.revision ?? old?.revision ?? 0,
          applied_revision: Math.max(event.revision, old?.applied_revision ?? 0), visible: projection.message && !projection.deleted ? 1 : 0,
        }, projection);
        updates.set(idKey, { row, projection });
      }
      signal?.throwIfAborted();
      // If fewer records remain, receipt-only gaps contain no message state.
      const remaining = last < through
        ? await db.getAllKeysFromIndex('encrypted_cache', 'by-chat-revision', IDBKeyRange.bound([chatId, last], [chatId, through], true, false), 1)
        : [];
      const complete = last >= through || remaining.length === 0;
      if (complete) last = through;
      const tx = db.transaction(['message_timeline', 'settings'], 'readwrite');
      if (fence.kind === 'lease') {
        const held = await tx.objectStore('settings').get(fence.lease_key);
        assertLeaseRecord(held?.kind === 'lease' ? held : undefined, fence);
      }
      const current = await tx.objectStore('settings').get(projectionKey(chatId));
      const cursor = current?.kind === 'json' ? current.value : 0;
      if (cursor !== after) { tx.abort(); throw new Error('History projection changed concurrently'); }
      for (const [idKey, update] of updates) {
        const actual = await tx.objectStore('message_timeline').get(idKey);
        if (actual?.applied_revision !== versions.get(idKey)) { tx.abort(); throw new Error('History target changed concurrently'); }
        await tx.objectStore('message_timeline').put(update.row);
      }
      await tx.objectStore('settings').put({ key: projectionKey(chatId), kind: 'json', value: last });
      await tx.done;
      return { processed: records.length, revision: last, complete };
    }, signal);
  } catch (error) {
    if (!(error instanceof CorruptTimelineRecord)) throw error;
    await beginProjectionRebuild(db, chatId, error.record, signal);
    return { processed: 0, revision: 0, complete: false };
  }
}

async function beginProjectionRebuild(db: IDBPDatabase<LocalDbSchema>, chatId: string, corrupt: EncryptedTimelineRecord, signal?: AbortSignal) {
  await withCryptoLock(db, `timeline:${chatId}`, async fence => {
    signal?.throwIfAborted();
    const tx = db.transaction(['message_timeline', 'settings'], 'readwrite');
    if (fence.kind === 'lease') {
      const held = await tx.objectStore('settings').get(fence.lease_key);
      assertLeaseRecord(held?.kind === 'lease' ? held : undefined, fence);
    }
    const current = await tx.objectStore('message_timeline').get(corrupt.timeline_key);
    const sameBytes = (left: Uint8Array, right: Uint8Array) => left.length === right.length && left.every((value, index) => value === right[index]);
    // Another tab may already have repaired this exact row while we waited.
    if (current && current.timeline_key.startsWith(`${chatId}:`) && current.chat_id === corrupt.chat_id && current.revision === corrupt.revision
      && current.applied_revision === corrupt.applied_revision && current.visible === corrupt.visible
      && sameBytes(current.nonce, corrupt.nonce) && sameBytes(current.ciphertext, corrupt.ciphertext)) {
      await tx.objectStore('settings').put({ key: rebuildKey(chatId), kind: 'json', value: true });
      await tx.objectStore('settings').put({ key: projectionKey(chatId), kind: 'json', value: 0 });
    }
    await tx.done;
  }, signal);
}

async function catchUpProjection(db: IDBPDatabase<LocalDbSchema>, key: CryptoKey, chatId: string, signal?: AbortSignal) {
  const through = await readChatSyncCursor(db, chatId);
  for (;;) {
    signal?.throwIfAborted();
    const result = await projectChatHistoryBatch(db, key, chatId, through, signal);
    if (result.complete) return;
    // Initial migration can be large. Release the event loop and the
    // per-chat lock between bounded chunks, and stop when the view is closed.
    await new Promise<void>(resolve => setTimeout(resolve, 0));
  }
}

export async function loadMessageTimelineWindow(
  db: IDBPDatabase<LocalDbSchema>, key: CryptoKey, chatId: string,
  options: HistoryWindowOptions = {},
): Promise<MessageTimelineWindow> {
  // Retry once after a derived-cache rebuild. A second authentication failure
  // indicates an ongoing storage problem, not a reason for an infinite loop.
  for (let attempt = 0; attempt < 2; attempt++) {
    try { return await readMessageTimelineWindow(db, key, chatId, options); }
    catch (error) {
      if (error instanceof LocalStorageError && error.type === 'STATE_VERSION_CONFLICT' && attempt === 0) continue;
      if (!(error instanceof CorruptTimelineRecord)) throw error;
      await beginProjectionRebuild(db, chatId, error.record, options.signal);
      if (attempt > 0) throw new LocalStorageError('CORRUPT_STATE', 'Message history could not be rebuilt', error);
    }
  }
  throw new LocalStorageError('CORRUPT_STATE', 'Message history could not be rebuilt');
}

async function readMessageTimelineWindow(
  db: IDBPDatabase<LocalDbSchema>, key: CryptoKey, chatId: string,
  options: HistoryWindowOptions,
): Promise<MessageTimelineWindow> {
  const { beforeRevision, afterRevision, signal } = options;
  if (beforeRevision !== undefined && afterRevision !== undefined) throw new Error('Choose one history direction');
  for (const revision of [beforeRevision, afterRevision]) {
    if (revision !== undefined && (!Number.isSafeInteger(revision) || revision < 1)) throw new Error('Invalid history boundary');
  }
  await catchUpProjection(db, key, chatId, signal);
  // A rebuild in another tab must not interleave a partially reconstructed
  // original with this window read before its later tombstone is reapplied.
  return withCryptoLock(db, `timeline:${chatId}`, async fence => {
    signal?.throwIfAborted();
    const rebuilding = await db.get('settings', rebuildKey(chatId));
    const watermark = await db.get('settings', projectionKey(chatId));
    const through = await readChatSyncCursor(db, chatId);
    if ((rebuilding?.kind === 'json' && rebuilding.value === true)
      || (watermark?.kind === 'json' && typeof watermark.value === 'number' ? watermark.value : 0) < through) {
      throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Message history changed before the window was read');
    }
    const range = IDBKeyRange.bound([chatId, 1, afterRevision ?? 0], [chatId, 1, beforeRevision ?? Number.MAX_SAFE_INTEGER], afterRevision !== undefined, beforeRevision !== undefined);
    const tx = db.transaction('message_timeline', 'readonly');
    let cursor = await tx.store.index('by-chat-visible-revision').openCursor(range, afterRevision === undefined ? 'prev' : 'next');
    const rows: EncryptedTimelineRecord[] = [];
    let bytes = 0;
    while (cursor && rows.length < HISTORY_WINDOW_MESSAGES) {
      const row = cursor.value;
      if (rows.length && bytes + row.ciphertext.byteLength > HISTORY_WINDOW_BYTES) break;
      rows.push(row); bytes += row.ciphertext.byteLength;
      cursor = await cursor.continue();
    }
    await tx.done;
    const messages: TimelineMessage[] = [];
    for (const row of rows) {
      signal?.throwIfAborted();
      const projection = await openProjection(key, row);
      if (projection.message && !projection.deleted) messages.push(projection.message);
    }
    messages.sort((left, right) => left.revision - right.revision);
    const replies = new Map<string, TimelineMessage>();
    const visibleIds = new Set(messages.map(message => message.message_id));
    for (const message of messages) {
      signal?.throwIfAborted();
      if (!message.reply_to_message_id) continue;
      const targetId = message.reply_to_message_id;
      const target = await db.get('message_timeline', timelineKey(chatId, targetId));
      if (!target) continue;
      const projection = await openProjection(key, target);
      if (projection.deleted) { message.reply_to_message_id = null; continue; }
      if (!visibleIds.has(targetId) && !replies.has(targetId) && projection.message) {
        const plaintext = cachedMessagePlaintext(projection.message);
        try {
          const content = decodeMessageContent(plaintext);
          const preview = encodeMessageContent(content.text.slice(0, 256), content.attachments.slice(0, 1));
          replies.set(targetId, { ...projection.message, plaintext: bytesToBase64Url(preview) });
          preview.fill(0);
        } finally { plaintext.fill(0); }
      }
    }
    const oldestRevision = messages[0]?.revision ?? null;
    const newestRevision = messages.at(-1)?.revision ?? null;
    const hasOlder = oldestRevision !== null && (await db.getAllKeysFromIndex('message_timeline', 'by-chat-visible-revision', IDBKeyRange.bound([chatId, 1, 0], [chatId, 1, oldestRevision], false, true), 1)).length > 0;
    const hasNewer = newestRevision !== null && (await db.getAllKeysFromIndex('message_timeline', 'by-chat-visible-revision', IDBKeyRange.bound([chatId, 1, newestRevision], [chatId, 1, Number.MAX_SAFE_INTEGER], true, false), 1)).length > 0;
    if (fence.kind === 'lease') {
      const held = await db.get('settings', fence.lease_key);
      assertLeaseRecord(held?.kind === 'lease' ? held : undefined, fence);
    }
    return { messages, replyPreviews: [...replies.values()], oldestRevision, newestRevision, hasOlder, hasNewer };
  }, signal);
}
