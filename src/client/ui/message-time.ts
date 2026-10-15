// Reuse ICU's formatter: constructing one per message on every render causes
// large native allocations that are not reflected in the JavaScript heap.
const messageTime = new Intl.DateTimeFormat([], { hour: '2-digit', minute: '2-digit' });

export function formatMessageTime(value: string): string {
  return messageTime.format(new Date(value));
}
