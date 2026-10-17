export const MAX_VISIBLE_MESSAGES = 80;
export const MAX_VISIBLE_MESSAGE_BYTES = 2 * 1024 * 1024;
export const MAX_CACHED_CHAT_WINDOWS = 2;

type VisibleContent = { text: string; attachments: readonly unknown[] };

/** Count UTF-16 text and bounded descriptor/metadata overhead retained by React. */
export function visibleMessageBytes(message: VisibleContent): number {
  return message.text.length * 2 + message.attachments.length * 512 + 1024;
}

export function boundVisibleMessages<T extends VisibleContent>(ordered: readonly T[]): T[] {
  const result: T[] = [];
  let bytes = 0;
  for (let index = ordered.length - 1; index >= 0 && result.length < MAX_VISIBLE_MESSAGES; index--) {
    const message = ordered[index]!;
    const size = visibleMessageBytes(message);
    if (bytes + size > MAX_VISIBLE_MESSAGE_BYTES) break;
    result.push(message); bytes += size;
  }
  return result.reverse();
}

export function rememberVisibleChat<T extends VisibleContent>(cache: Map<string, T[]>, chatId: string, messages: readonly T[]): T[] {
  const bounded = boundVisibleMessages(messages);
  cache.delete(chatId);
  cache.set(chatId, bounded);
  while (cache.size > MAX_CACHED_CHAT_WINDOWS) cache.delete(cache.keys().next().value!);
  return bounded;
}
