import {serverWireRequest} from "../crypto/server-message-transport";
import type { IDBPDatabase } from 'idb';
import type { RealtimeMessageAck } from '../../shared/contracts/realtime';
import {
  readChatOutboxBatch,
  sendPendingOutboxRecord,
  setOutboxTransportState,
  transitionOutboxRecord,
} from '../storage/outbox';
import { confirmOutgoingCacheRevision } from '../storage/outgoing-confirmation';
import type { LocalDbSchema, PendingOutboxRecord } from '../storage/schema';
import { ChatRealtimeClient } from '../transport/realtime';

export const REALTIME_ACK_SLOW_MS = 800;
export const REALTIME_ACK_FALLBACK_MS = 5_000;
const REALTIME_CONNECT_GRACE_MS = 700;
const REALTIME_READY_POLL_MS = 10;
const activeDeliveries = new WeakMap<IDBPDatabase<LocalDbSchema>, Map<string, Promise<PendingOutboxRecord>>>();

/**
 * Deliver an already encrypted/durable outbox record. WebSocket is primary;
 * HTTP starts immediately on realtime failure. A healthy/open socket gets a
 * bounded ACK grace period so transient server backpressure is not mistaken
 * for transport loss.
 * Ordered messages additionally wait until every lower sender_sequence has
 * committed, so expected server-side backpressure cannot create false fallback.
 * Both transports send record.request unchanged and D1 idempotency converges
 * their race to one definitive message_id/revision.
 */
export async function deliverPreparedMessageWsFirst(
  db: IDBPDatabase<LocalDbSchema>,
  realtime: ChatRealtimeClient | null,
  record: PendingOutboxRecord,
): Promise<PendingOutboxRecord> {
  let deliveries = activeDeliveries.get(db);
  if (!deliveries) {
    deliveries = new Map();
    activeDeliveries.set(db, deliveries);
  }
  const existing = deliveries.get(record.client_message_id);
  if (existing) return existing;

  const delivery = deliverPreparedMessageWsFirstOnce(db, realtime, record);
  deliveries.set(record.client_message_id, delivery);
  try {
    return await delivery;
  } finally {
    if (deliveries.get(record.client_message_id) === delivery) deliveries.delete(record.client_message_id);
  }
}

async function deliverPreparedMessageWsFirstOnce(
  db: IDBPDatabase<LocalDbSchema>,
  realtime: ChatRealtimeClient | null,
  staleRecord: PendingOutboxRecord,
): Promise<PendingOutboxRecord> {
  // Recovery, connectivity and the interactive queue may all discover the
  // same durable record. Always re-read inside the single-flight section so a
  // stale PENDING snapshot cannot retransmit a message that just committed.
  const record = await db.get('pending_outbox', staleRecord.client_message_id);
  if (!record) throw new Error(`Outgoing message ${staleRecord.client_message_id} disappeared before delivery`);
  if (record.status === 'COMMITTED' || record.status === 'FAILED') return record;

  // Pre-upgrade/legacy records without sender_sequence cannot use message.send;
  // retain HTTP recovery compatibility without re-encrypting them.
  if (record.request.sender_sequence === undefined) {
    return deliverHttpFallback(db, record.client_message_id);
  }

  // A newly selected/re-authenticated chat can become renderable a few
  // milliseconds before its WebSocket finishes the mandatory catch-up. Do not
  // mistake that normal CONNECTING/HTTP_SYNC phase for a transport failure.
  // The ACK deadline starts only after message.send can actually be emitted.
  if (!realtime) return deliverHttpFallback(db, record.client_message_id);
  if (!realtime.canSendMessages) {
    const ready = await waitForRealtimeReady(realtime, REALTIME_CONNECT_GRACE_MS);
    if (!ready) {
      await setOutboxTransportState(db, record.client_message_id, 'RETRYING', 'REALTIME_NOT_READY');
      return deliverHttpFallback(db, record.client_message_id);
    }
  }

  let httpPromise: Promise<PendingOutboxRecord> | null = null;
  const startHttp = (): Promise<PendingOutboxRecord> => {
    if (!httpPromise) httpPromise = deliverOrderedHttpFallback(db, record);
    return httpPromise;
  };

  await setOutboxTransportState(db, record.client_message_id, 'WS_IN_FLIGHT');
  const wsAttempt = deliverViaRealtime(db, realtime, record).catch(async (error) => {
    await setOutboxTransportState(
      db,
      record.client_message_id,
      'RETRYING',
      error instanceof Error ? error.name : 'REALTIME_ERROR',
    );
    return startHttp();
  });

  let timer: number | undefined;
  const fallbackAttempt = new Promise<PendingOutboxRecord>((resolve, reject) => {
    const beginFallback = () => {
      void startHttp().then(resolve, reject);
    };
    timer = globalThis.setTimeout(() => {
      if (!realtime.canSendMessages) {
        beginFallback();
        return;
      }
      // The socket is still READY/OPEN. Keep WS primary for a bounded grace
      // period; close/error/NACK rejects wsAttempt and starts HTTP immediately.
      timer = globalThis.setTimeout(
        beginFallback,
        REALTIME_ACK_FALLBACK_MS - REALTIME_ACK_SLOW_MS,
      ) as unknown as number;
    }, REALTIME_ACK_SLOW_MS) as unknown as number;
  });

  try {
    const first = await Promise.race([wsAttempt, fallbackAttempt]);
    if (isTerminal(first)) return first;

    // A retryable first result may race a still-live second transport. If HTTP
    // was started, give that definitive attempt precedence before returning a
    // pending state to the UI.
    if (httpPromise) {
      const http = await httpPromise;
      if (isTerminal(http)) return http;
    }
    return await db.get('pending_outbox', record.client_message_id) ?? first;
  } finally {
    if (timer !== undefined) globalThis.clearTimeout(timer);
  }
}

/**
 * Recover durable records after reload/PWA restart. Recovery is deliberately
 * ordered by sender_sequence because the socket may still be unavailable and
 * HTTP fallback must never commit sequence N+1 ahead of N.
 */
export async function resumePendingOutboxWsFirst(
  db: IDBPDatabase<LocalDbSchema>,
  realtime: ChatRealtimeClient | null,
  chatId: string,
  onResult?: (record: PendingOutboxRecord) => void,
): Promise<void> {
  const records = (await readChatOutboxBatch(db, chatId, ['PENDING', 'VERIFY_ACCEPTANCE'])).sort(compareRecoveryOrder);

  for (const record of records) {
    const result = await deliverPreparedMessageWsFirst(db, realtime, record);
    onResult?.(result);
    if (record.request.sender_sequence !== undefined && result.status !== 'COMMITTED') break;
  }
}

async function deliverViaRealtime(
  db: IDBPDatabase<LocalDbSchema>,
  realtime: ChatRealtimeClient,
  record: PendingOutboxRecord,
): Promise<PendingOutboxRecord> {
  const ack = await realtime.sendMessage(await serverWireRequest(record,db));
  return applyRealtimeAck(db, record, ack);
}

async function waitForRealtimeReady(realtime: ChatRealtimeClient, timeoutMs: number): Promise<boolean> {
  if (realtime.canSendMessages) return true;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await delay(REALTIME_READY_POLL_MS);
    if (realtime.canSendMessages) return true;
  }
  return realtime.canSendMessages;
}

async function applyRealtimeAck(
  db: IDBPDatabase<LocalDbSchema>,
  record: PendingOutboxRecord,
  ack: RealtimeMessageAck,
): Promise<PendingOutboxRecord> {
  if (ack.chat_id !== record.chat_id || ack.client_message_id !== record.client_message_id) {
    throw new Error('Realtime ACK does not match durable outbox record');
  }
  const committed = await transitionOutboxRecord(
    db,
    record.client_message_id,
    'COMMITTED',
    undefined,
    true,
    undefined,
    ack,
  );
  if (!committed) throw new Error(`Outgoing message ${record.client_message_id} disappeared after realtime ACK`);
  await confirmOutgoingCacheRevision(db, record.chat_id, record.client_message_id, ack.message_id, ack.revision);
  return committed;
}

async function deliverOrderedHttpFallback(
  db: IDBPDatabase<LocalDbSchema>,
  record: PendingOutboxRecord,
): Promise<PendingOutboxRecord> {
  const turn = await waitForOrderedFallbackTurn(db, record);
  if (!turn) {
    const current = await db.get('pending_outbox', record.client_message_id);
    if (!current) throw new Error(`Outgoing message ${record.client_message_id} disappeared behind blocked ordered fallback`);
    return current;
  }

  // The WebSocket may have committed this message while it was waiting behind
  // an earlier sender_sequence. Re-read before issuing any HTTP request so a
  // healthy realtime burst never creates a redundant fallback POST.
  const current = await db.get('pending_outbox', record.client_message_id);
  if (!current) throw new Error(`Outgoing message ${record.client_message_id} disappeared before ordered HTTP fallback`);
  if (isTerminal(current)) return current;
  return deliverHttpFallback(db, record.client_message_id);
}

async function waitForOrderedFallbackTurn(
  db: IDBPDatabase<LocalDbSchema>,
  record: PendingOutboxRecord,
): Promise<boolean> {
  const sequence = record.request.sender_sequence;
  if (sequence === undefined) return true;
  const deadline = performance.now() + REALTIME_ACK_FALLBACK_MS;

  while (true) {
    const current = await db.get('pending_outbox', record.client_message_id);
    if (!current || isTerminal(current)) return false;
    const records: PendingOutboxRecord[] = [];
    for (const status of ['FAILED', 'NEEDS_REENCRYPT', 'PENDING', 'VERIFY_ACCEPTANCE'] as const) {
      const earlier = await db.getFromIndex('pending_outbox', 'by-chat-device-status-sequence', IDBKeyRange.bound(
        [record.chat_id, record.sender_device_id, status, 0], [record.chat_id, record.sender_device_id, status, sequence], false, true));
      if (earlier) records.push(earlier);
    }
    let waiting = false;
    for (const candidate of records) {
      if (candidate.client_message_id === record.client_message_id
        || candidate.sender_device_id !== record.sender_device_id
        || candidate.request.sender_sequence === undefined
        || candidate.request.sender_sequence >= sequence) continue;

      if (candidate.status === 'FAILED' || candidate.status === 'NEEDS_REENCRYPT') {
        // A later sender_sequence cannot safely jump over an earlier message
        // that will not commit as-is. Leave this record durable for the normal
        // recovery/sequence-repair path instead of manufacturing HTTP gaps.
        return false;
      }
      if (candidate.status !== 'COMMITTED') waiting = true;
    }
    if (!waiting) return true;
    // Preserve the durable record for a later recovery pass; never skip the
    // predecessor or retain a polling task indefinitely while it is blocked.
    if (performance.now() >= deadline) return false;
    await delay(REALTIME_READY_POLL_MS);
  }
}

async function deliverHttpFallback(
  db: IDBPDatabase<LocalDbSchema>,
  clientMessageId: string,
): Promise<PendingOutboxRecord> {
  const current = await db.get('pending_outbox', clientMessageId);
  if (!current) throw new Error(`Outgoing message ${clientMessageId} disappeared before HTTP fallback`);
  if (current.status === 'COMMITTED' || current.status === 'FAILED') return current;

  await setOutboxTransportState(db, clientMessageId, 'HTTP_FALLBACK_IN_FLIGHT');
  const result = await sendPendingOutboxRecord(db, clientMessageId);
  if (result.status === 'COMMITTED' && result.server_revision !== undefined) {
    if (!result.server_message_id) throw new Error('Committed HTTP fallback omitted server_message_id');
    await confirmOutgoingCacheRevision(db, result.chat_id, result.client_message_id, result.server_message_id, result.server_revision);
  } else if (result.status === 'PENDING' || result.status === 'VERIFY_ACCEPTANCE') {
    await setOutboxTransportState(db, clientMessageId, 'RETRYING', result.last_error_type);
  }
  return await db.get('pending_outbox', clientMessageId) ?? result;
}

function compareRecoveryOrder(left: PendingOutboxRecord, right: PendingOutboxRecord): number {
  const leftSequence = left.request.sender_sequence;
  const rightSequence = right.request.sender_sequence;
  if (leftSequence !== undefined && rightSequence !== undefined && leftSequence !== rightSequence) {
    return leftSequence - rightSequence;
  }
  if (leftSequence !== undefined && rightSequence === undefined) return -1;
  if (leftSequence === undefined && rightSequence !== undefined) return 1;
  return left.created_at.localeCompare(right.created_at) || left.client_message_id.localeCompare(right.client_message_id);
}

function isTerminal(record: PendingOutboxRecord): boolean {
  return record.status === 'COMMITTED' || record.status === 'FAILED' || record.status === 'NEEDS_REENCRYPT';
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, ms));
}
