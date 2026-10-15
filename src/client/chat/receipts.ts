import type { IDBPDatabase } from 'idb';
import {
  ReceiptBatchResponseSchema,
  ReceiptResponseSchema,
  type ReceiptState,
} from '../../shared/contracts/receipts';
import { uuidv7 } from '../../shared/ids/uuidv7';
import type { LocalDbSchema } from '../storage/schema';
import { ApiError, apiFetch } from '../transport/api';

type ReceiptCandidate = {
  direction: 'INCOMING' | 'OUTGOING';
  message_id: string | null;
};

type ReceiptQueue = {
  db: IDBPDatabase<LocalDbSchema>;
  candidates: Map<string, ReceiptCandidate>;
  running: boolean;
};

const DELIVERED_VALUE = 1;
const READ_VALUE = 2;
// Advisory acknowledgements share a request during continuous traffic.
// This timer never delays message encryption, delivery or display.
const RECEIPT_COALESCE_MS = 250;
const MAX_RECEIPTS_PER_REQUEST = 100;
const receiptQueues = new Map<string, ReceiptQueue>();

export async function sendReceiptHttp(chatId: string, messageId: string, state: ReceiptState) {
  return apiFetch(
    `/api/v1/chats/${encodeURIComponent(chatId)}/receipts`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': uuidv7(),
      },
      body: JSON.stringify({ message_id: messageId, state }),
    },
    (value) => ReceiptResponseSchema.parse(value),
    { retryMode: 'idempotent' },
  );
}

export async function sendReceiptBatchHttp(
  chatId: string,
  receipts: Array<{ message_id: string; state: ReceiptState }>,
) {
  return apiFetch(
    `/api/v1/chats/${encodeURIComponent(chatId)}/receipts/batch`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': uuidv7(),
      },
      body: JSON.stringify({ receipts }),
    },
    (value) => ReceiptBatchResponseSchema.parse(value),
    { retryMode: 'idempotent' },
  );
}

export async function reconcileDeliveredReceipts(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  messages: ReceiptCandidate[],
): Promise<void> {
  const pending: Array<{ message_id: string; state: 'READ' }> = [];
  const ids = [...new Set(messages.flatMap(message => message.direction === 'INCOMING' && message.message_id ? [message.message_id] : []))];
  if (ids.length === 0) return;
  const read = db.transaction('settings', 'readonly');
  const markers = await Promise.all(ids.map(id => read.store.get(receiptMarkerKey(id))));
  await read.done;
  for (const [index, id] of ids.entries()) {
    const marker = markers[index];
    const prior = marker?.kind === 'json' && typeof marker.value === 'number' && Number.isSafeInteger(marker.value)
      ? marker.value
      : 0;
    if (prior < READ_VALUE) pending.push({ message_id: id, state: 'READ' });
  }
  if (pending.length === 0) return;

  try {
    for (let offset = 0; offset < pending.length; offset += MAX_RECEIPTS_PER_REQUEST) {
      const chunk = pending.slice(offset, offset + MAX_RECEIPTS_PER_REQUEST);
      const responses = chunk.length === 1
        ? { receipts: [await sendReceiptHttp(chatId, chunk[0]!.message_id, 'READ')] }
        : await sendReceiptBatchHttp(chatId, chunk);
      const write = db.transaction('settings', 'readwrite');
      await Promise.all(responses.receipts.map(receipt => write.store.put({
        key: receiptMarkerKey(receipt.message_id),
        kind: 'json',
        value: receipt.state === 'READ' ? READ_VALUE : DELIVERED_VALUE,
      })));
      await write.done;
    }
  } catch (error) {
    // The plaintext and ratchet transition are already durable locally. A
    // retryable transport failure intentionally leaves no local marker, so
    // the next HTTP sync retries this monotonic receipt. If the server
    // committed all or part of the batch but the ACK was lost, retries are
    // harmless because receipt state only moves forward.
    if (error instanceof ApiError && !error.retryable) throw error;
  }
}

export function scheduleDeliveredReceipts(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  messages: ReceiptCandidate[],
): void {
  const queue = receiptQueues.get(chatId) ?? { db, candidates: new Map<string, ReceiptCandidate>(), running: false };
  receiptQueues.set(chatId, queue);
  for (const message of messages) {
    if (message.direction === 'INCOMING' && message.message_id) queue.candidates.set(message.message_id, message);
  }
  if (queue.running || queue.candidates.size === 0) return;
  queue.running = true;
  void drainReceiptQueue(chatId, queue);
}

async function drainReceiptQueue(chatId: string, queue: ReceiptQueue): Promise<void> {
  try {
    while (queue.candidates.size > 0) {
      // Coalesce advisory receipts without delaying decryption or rendering.
      // Recovery/sync can reschedule them if this tab closes before the flush.
      await new Promise(resolve => globalThis.setTimeout(resolve, RECEIPT_COALESCE_MS));
      const candidates = [...queue.candidates.values()];
      queue.candidates.clear();
      try {
        await reconcileDeliveredReceipts(queue.db, chatId, candidates);
      } catch {
        // Delivery receipts are advisory and idempotent. A later chat sync
        // schedules them again without delaying decrypted message rendering.
      }
    }
  } finally {
    queue.running = false;
    if (queue.candidates.size === 0) receiptQueues.delete(chatId);
    else scheduleDeliveredReceipts(queue.db, chatId, [...queue.candidates.values()]);
  }
}

function receiptMarkerKey(messageId: string): string {
  return `receipt:${messageId}`;
}
