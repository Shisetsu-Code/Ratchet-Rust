export type ReceiptUpdate = { message_id: string; state: 'DELIVERED' | 'READ' };
type ReceiptRow = { message_id: string | null; direction: string; receipt_state: 'DELIVERED' | 'READ' | null };
export function applyReceiptUpdates<T extends ReceiptRow>(messages: T[], updates: readonly ReceiptUpdate[]): T[] {
  if (!updates.length) return messages;
  const states = new Map<string, ReceiptUpdate['state']>();
  for (const update of updates) {
    if (states.get(update.message_id) !== 'READ') states.set(update.message_id, update.state);
  }
  return messages.map(message => {
    const state = message.message_id ? states.get(message.message_id) : undefined;
    if (message.direction !== 'OUTGOING' || !state || message.receipt_state === 'READ' || message.receipt_state === state) return message;
    return { ...message, receipt_state: state };
  });
}
