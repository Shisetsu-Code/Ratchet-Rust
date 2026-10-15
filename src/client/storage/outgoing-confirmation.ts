import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema } from './schema';
import { promoteOutgoingCache } from './message-cache';

/**
 * A sender ACK proves this logical message has a definitive D1 revision, but it
 * does not prove every earlier global chat revision has been applied locally.
 * Promote only the outgoing cache record here; reconciliation advances the
 * chat cursor once revisions are contiguous.
 */
export async function confirmOutgoingCacheRevision(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  clientMessageId: string,
  messageId: string,
  revision: number,
): Promise<void> {
  if (!Number.isSafeInteger(revision) || revision <= 0) throw new Error('Invalid committed message revision');
  const outbox = await db.get('pending_outbox', clientMessageId);
  if (!outbox) throw new Error(`Outgoing message ${clientMessageId} is missing while confirming its cache`);
  await promoteOutgoingCache(db, outbox.sender_device_id, chatId, clientMessageId, messageId, revision, {
    mutation: outbox.request.mutation ?? null,
    reply_to_message_id: outbox.request.reply_to_message_id ?? null,
  });
}
