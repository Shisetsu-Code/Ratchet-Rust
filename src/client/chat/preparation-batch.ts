type QueueEntry = {chatId: string; attachments: readonly unknown[]; mutation?: unknown; replyToMessageId?: string};
const MAX_PREPARATION_BATCH = 8;
/** Only consume entries already present: never wait to fill a batch. */
export function selectPreparationBatch<T extends QueueEntry>(queue: readonly T[]): T[] {
  const first = queue[0];
  if (!first) return [];
  const plain = (entry: T) => !entry.attachments.length && !entry.mutation && !entry.replyToMessageId;
  if (!plain(first)) return [first];
  const result: T[] = [];
  for (const entry of queue) {
    if (result.length === MAX_PREPARATION_BATCH || entry.chatId !== first.chatId || !plain(entry)) break;
    result.push(entry);
  }
  return result;
}
