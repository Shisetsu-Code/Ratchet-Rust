import type { IDBPDatabase } from 'idb';
import { BrowserSecureMessagingEngine } from '../crypto/engine';
import { LocalStorageError } from '../storage/errors';
import { sendPendingOutboxBatch, setOutboxTransportState } from '../storage/outbox';
import type { LocalDbSchema, PendingOutboxRecord } from '../storage/schema';
import { ApiError } from '../transport/api';
import { preconnectRealtimeSocket } from '../transport/realtime';
import { ensureSenderSequenceSeed } from './sender-sequence';

export type SecureSendInput = {
  chat_id: string;
  sender_user_id: string;
  sender_device_id: string;
  client_message_id: string;
  plaintext?: Uint8Array;
  attachment_ids?: string[];
  mutation?: { target_message_id: string; type: 'EDIT' | 'TOMBSTONE' };
  reply_to_message_id?: string;
};

export type StreamingSendStart = {
  queued: PendingOutboxRecord;
  completion: Promise<PendingOutboxRecord>;
};

type EngineCacheEntry = {
  engine: BrowserSecureMessagingEngine;
  last_used_at: number;
};

const SEND_MICROBATCH_SIZE = 2;
const ENGINE_IDLE_TTL_MS = 2 * 60_000;
const engineCache = new WeakMap<IDBPDatabase<LocalDbSchema>, Map<string, EngineCacheEntry>>();

/** Legacy HTTP transport lane; the interactive UI no longer uses it. */
const orderedTransportLanes = new WeakMap<
  IDBPDatabase<LocalDbSchema>,
  Map<string, Promise<PendingOutboxRecord>>
>();

export async function warmSecureChatSendContext(
  db: IDBPDatabase<LocalDbSchema>,
  input: Pick<SecureSendInput, 'chat_id' | 'sender_user_id' | 'sender_device_id'>,
): Promise<void> {
  // Start the socket handshake immediately while the crypto/send context warms.
  // ChatRealtimeClient later adopts this exact socket; no duplicate connection
  // is created and no buffered event becomes authoritative without D1/HTTP.
  preconnectRealtimeSocket(input.chat_id);
  const engine = secureEngine(db, input.sender_user_id, input.sender_device_id);
  await Promise.all([
    ensureSenderSequenceSeed(db, input.chat_id, input.sender_device_id),
    engine.canBatchMessage(input.chat_id),
  ]);
}

/**
 * WS-first interactive preparation primitive.
 *
 * It performs exactly one logical encryption, atomically persists ratchet
 * advancement + ciphertext outbox + local encrypted cache + sender_sequence,
 * and returns. It performs no WebSocket or HTTP I/O.
 */
export async function prepareSecureChatMessage(
  db: IDBPDatabase<LocalDbSchema>,
  input: SecureSendInput,
): Promise<PendingOutboxRecord> {
  const engine = secureEngine(db, input.sender_user_id, input.sender_device_id);
  await ensureSenderSequenceSeed(db, input.chat_id, input.sender_device_id);

  let queued: PendingOutboxRecord | null = null;
  if (input.plaintext && (input.attachment_ids?.length ?? 0) === 0 && !input.mutation && !input.reply_to_message_id) {
    try {
      queued = await engine.queueStreamingMessage({
        chat_id: input.chat_id,
        client_message_id: input.client_message_id,
        plaintext: input.plaintext,
      });
    } catch (error) {
      // An established-target cache can legitimately outlive its IndexedDB
      // pairwise session (for example after local session recovery/cleanup).
      // Treat only that precise condition as a stale hot cache: clear it and
      // fall through to queueMessage(), which resolves authoritative targets
      // again and performs PQXDH bootstrap using the existing device identity.
      if (!(error instanceof LocalStorageError)
        || error.type !== 'CORRUPT_STATE'
        || !error.message.startsWith('Missing ratchet session ')) {
        throw error;
      }
      engine.clearHotSendContext(input.chat_id);
    }
  }

  queued ??= await engine.queueMessage({
    chat_id: input.chat_id,
    client_message_id: input.client_message_id,
    ...(input.plaintext ? { plaintext: input.plaintext } : {}),
    ...(input.attachment_ids ? { attachment_ids: input.attachment_ids } : {}),
    ...(input.mutation ? { mutation: input.mutation } : {}),
    ...(input.reply_to_message_id ? { reply_to_message_id: input.reply_to_message_id } : {}),
    allocate_sender_sequence: true,
  });

  if (queued.request.sender_sequence === undefined) {
    throw new Error('Interactive secure message was persisted without sender_sequence');
  }
  const updated = await setOutboxTransportState(db, queued.client_message_id, 'DURABLE_LOCAL');
  return updated ?? queued;
}

/** Prepare an atomic prefix; bootstrap falls back to just the first entry.
 * A partial fallback must never leave the caller unaware of durable records.
 */
export async function prepareSecureChatMessages(
  db: IDBPDatabase<LocalDbSchema>, inputs: SecureSendInput[],
): Promise<PendingOutboxRecord[]> {
  const first = inputs[0];
  if (!first) return [];
  if (inputs.length === 1 || inputs.some(input => input.chat_id !== first.chat_id
    || input.sender_user_id !== first.sender_user_id || input.sender_device_id !== first.sender_device_id
    || !input.plaintext || input.attachment_ids?.length || input.mutation || input.reply_to_message_id)) {
    return [await prepareSecureChatMessage(db, first)];
  }
  const engine = secureEngine(db, first.sender_user_id, first.sender_device_id);
  await ensureSenderSequenceSeed(db, first.chat_id, first.sender_device_id);
  let records: PendingOutboxRecord[] | null = null;
  try {
    records = await engine.queueStreamingBatch(inputs);
  } catch (error) {
    if (!(error instanceof LocalStorageError) || error.type !== 'CORRUPT_STATE'
      || !error.message.startsWith('Missing ratchet session ')) throw error;
    engine.clearHotSendContext(first.chat_id);
  }
  if (!records) return [await prepareSecureChatMessage(db, first)];
  if (records.some(record => record.request.sender_sequence === undefined)) {
    throw new Error('Interactive secure batch was persisted without sender_sequence');
  }
  return records;
}

/**
 * Recipient/recovery-set rejection is not a transport retry. The old ciphertext
 * is cryptographically bound to an obsolete authorized target set, therefore a
 * fresh envelope set is required. The encrypted retry material is opened only
 * locally, while client_message_id and sender_sequence remain unchanged.
 */
export async function refreshRejectedSecureChatMessage(
  db: IDBPDatabase<LocalDbSchema>,
  input: Pick<SecureSendInput, 'chat_id' | 'sender_user_id' | 'sender_device_id' | 'client_message_id'>,
): Promise<PendingOutboxRecord> {
  const current = await db.get('pending_outbox', input.client_message_id);
  if (!current) throw new Error(`Rejected outbox ${input.client_message_id} is missing`);
  if (current.status !== 'NEEDS_REENCRYPT') return current;

  const engine = secureEngine(db, input.sender_user_id, input.sender_device_id);
  engine.clearHotSendContext(input.chat_id);
  const refreshed = await engine.queueMessage({
    chat_id: input.chat_id,
    client_message_id: input.client_message_id,
    ...(current.request.sender_sequence !== undefined ? { sender_sequence: current.request.sender_sequence } : {}),
    ...(current.request.mutation ? { mutation: current.request.mutation } : {}),
    ...(current.request.reply_to_message_id ? { reply_to_message_id: current.request.reply_to_message_id } : {}),
  });
  if (current.request.sender_sequence !== undefined
    && refreshed.request.sender_sequence !== current.request.sender_sequence) {
    throw new Error('Recipient-set refresh changed sender_sequence');
  }
  const updated = await setOutboxTransportState(db, refreshed.client_message_id, 'DURABLE_LOCAL');
  return updated ?? refreshed;
}

/**
 * Legacy completion primitive retained only for compatibility with callers
 * that have not migrated to deliverPreparedMessageWsFirst().
 */
export async function startSecureChatMessage(
  db: IDBPDatabase<LocalDbSchema>,
  input: SecureSendInput,
): Promise<StreamingSendStart> {
  const engine = secureEngine(db, input.sender_user_id, input.sender_device_id);
  const queued = await prepareSecureChatMessage(db, input);

  const flush = () => engine.flushPreparedMessage({
    chat_id: input.chat_id,
    client_message_id: input.client_message_id,
    ...(input.plaintext ? { plaintext: input.plaintext } : {}),
    ...(input.attachment_ids ? { attachment_ids: input.attachment_ids } : {}),
    ...(queued.request.sender_sequence !== undefined ? { sender_sequence: queued.request.sender_sequence } : {}),
  });

  const completion = scheduleOrderedTransport(
    db,
    input.chat_id,
    input.sender_device_id,
    input.client_message_id,
    flush,
  );

  return { queued, completion };
}

export async function queueSecureChatMessage(
  db: IDBPDatabase<LocalDbSchema>,
  input: SecureSendInput,
): Promise<PendingOutboxRecord> {
  return prepareSecureChatMessage(db, input);
}

export async function sendSecureChatMessage(
  db: IDBPDatabase<LocalDbSchema>,
  input: SecureSendInput,
): Promise<PendingOutboxRecord> {
  const started = await startSecureChatMessage(db, input);
  return started.completion;
}

export async function canBatchSecureChatMessages(
  db: IDBPDatabase<LocalDbSchema>,
  input: Pick<SecureSendInput, 'chat_id' | 'sender_user_id' | 'sender_device_id'>,
): Promise<boolean> {
  const engine = secureEngine(db, input.sender_user_id, input.sender_device_id);
  return engine.canBatchMessage(input.chat_id);
}

/**
 * Legacy throughput API retained for recovery/tests only. Interactive user
 * sends never call this endpoint or function.
 */
export async function sendSecureChatBatch(
  db: IDBPDatabase<LocalDbSchema>,
  inputs: SecureSendInput[],
): Promise<PendingOutboxRecord[] | null> {
  if (inputs.length < 2) return null;
  const first = inputs[0]!;
  if (inputs.some((input) => input.chat_id !== first.chat_id
    || input.sender_user_id !== first.sender_user_id
    || input.sender_device_id !== first.sender_device_id
    || (input.attachment_ids?.length ?? 0) > 0)) return null;

  const engine = secureEngine(db, first.sender_user_id, first.sender_device_id);
  if (!(await engine.canBatchMessage(first.chat_id))) return null;

  const results: PendingOutboxRecord[] = [];
  for (let offset = 0; offset < inputs.length; offset += SEND_MICROBATCH_SIZE) {
    const chunk = inputs.slice(offset, offset + SEND_MICROBATCH_SIZE);
    let records = await engine.queueEstablishedBatch(chunk.map((input) => ({
      chat_id: input.chat_id,
      client_message_id: input.client_message_id,
      ...(input.plaintext ? { plaintext: input.plaintext } : {}),
    })));

    if (!records) {
      records = [];
      for (const input of chunk) {
        records.push(await engine.queueMessage({
          chat_id: input.chat_id,
          client_message_id: input.client_message_id,
          ...(input.plaintext ? { plaintext: input.plaintext } : {}),
        }));
      }
    }

    const pending = records.filter((record) => record.status === 'PENDING');
    try {
      if (pending.length >= 2) {
        const committed = await sendPendingOutboxBatch(db, pending);
        const committedById = new Map(committed.map((record) => [record.client_message_id, record]));
        for (let index = 0; index < records.length; index += 1) {
          const currentRecord = records[index]!;
          records[index] = committedById.get(currentRecord.client_message_id) ?? currentRecord;
        }
      } else if (pending.length === 1) {
        const pendingRecord = pending[0]!;
        const input = chunk.find((candidate) => candidate.client_message_id === pendingRecord.client_message_id);
        if (!input) throw new Error('Pending microbatch record lost its secure-send input');
        const committed = await engine.sendMessage({
          chat_id: input.chat_id,
          client_message_id: input.client_message_id,
          ...(input.plaintext ? { plaintext: input.plaintext } : {}),
        });
        const index = records.findIndex((record) => record.client_message_id === committed.client_message_id);
        if (index >= 0) records[index] = committed;
      }
    } catch (error) {
      if (!(error instanceof ApiError) || (error.type !== 'RECIPIENT_SET_STALE' && error.type !== 'RECOVERY_SET_STALE')) throw error;
      engine.clearHotSendContext(first.chat_id);
      for (let index = 0; index < chunk.length; index += 1) {
        const input = chunk[index]!;
        records[index] = await engine.sendMessage({
          chat_id: input.chat_id,
          client_message_id: input.client_message_id,
          ...(input.plaintext ? { plaintext: input.plaintext } : {}),
        });
      }
    }
    results.push(...records);
  }
  return results;
}

export async function sendQueuedSecureChatMessages(
  db: IDBPDatabase<LocalDbSchema>,
  records: PendingOutboxRecord[],
): Promise<PendingOutboxRecord[]> {
  return sendPendingOutboxBatch(db, records);
}

export function clearSecureChatSendContext(
  db: IDBPDatabase<LocalDbSchema>,
  senderUserId: string,
  senderDeviceId: string,
  chatId?: string,
): void {
  const pool = engineCache.get(db);
  if (pool) {
    const key = engineKey(senderUserId, senderDeviceId);
    const entry = pool.get(key);
    if (entry) {
      entry.engine.clearHotSendContext(chatId);
      if (!chatId) pool.delete(key);
    }
  }

  const lanes = orderedTransportLanes.get(db);
  if (!lanes) return;
  if (chatId) lanes.delete(transportLaneKey(chatId, senderDeviceId));
  else {
    for (const key of lanes.keys()) {
      if (key.startsWith(`${senderDeviceId}\u0000`)) lanes.delete(key);
    }
  }
}

function scheduleOrderedTransport(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  senderDeviceId: string,
  clientMessageId: string,
  send: () => Promise<PendingOutboxRecord>,
): Promise<PendingOutboxRecord> {
  let lanes = orderedTransportLanes.get(db);
  if (!lanes) {
    lanes = new Map<string, Promise<PendingOutboxRecord>>();
    orderedTransportLanes.set(db, lanes);
  }

  const key = transportLaneKey(chatId, senderDeviceId);
  const predecessor = lanes.get(key);
  let predecessorBlocked = false;
  const gate = predecessor
    ? predecessor.then(
      (record) => { predecessorBlocked = record.status !== 'COMMITTED'; },
      () => { predecessorBlocked = true; },
    )
    : Promise.resolve();

  const completion = gate.then(async () => {
    if (predecessorBlocked) {
      const current = await db.get('pending_outbox', clientMessageId);
      if (!current) throw new Error(`Outgoing message ${clientMessageId} disappeared behind blocked transport lane`);
      return current;
    }
    return send();
  });

  lanes.set(key, completion);
  void completion.finally(() => {
    const currentLanes = orderedTransportLanes.get(db);
    if (currentLanes?.get(key) === completion) currentLanes.delete(key);
  }).catch(() => undefined);
  return completion;
}

function transportLaneKey(chatId: string, senderDeviceId: string): string {
  return `${senderDeviceId}\u0000${chatId}`;
}

function secureEngine(
  db: IDBPDatabase<LocalDbSchema>,
  senderUserId: string,
  senderDeviceId: string,
): BrowserSecureMessagingEngine {
  let pool = engineCache.get(db);
  if (!pool) {
    pool = new Map<string, EngineCacheEntry>();
    engineCache.set(db, pool);
  }

  const now = Date.now();
  for (const [key, entry] of pool) {
    if (now - entry.last_used_at > ENGINE_IDLE_TTL_MS) {
      entry.engine.clearHotSendContext();
      pool.delete(key);
    }
  }

  const key = engineKey(senderUserId, senderDeviceId);
  const cached = pool.get(key);
  if (cached) {
    cached.last_used_at = now;
    return cached.engine;
  }

  const engine = new BrowserSecureMessagingEngine(db, senderUserId, senderDeviceId);
  pool.set(key, { engine, last_used_at: now });
  return engine;
}

function engineKey(senderUserId: string, senderDeviceId: string): string {
  return `${senderUserId}\u0000${senderDeviceId}`;
}
