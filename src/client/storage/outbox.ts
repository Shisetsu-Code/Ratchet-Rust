import {serverWireRequest} from "../crypto/server-message-transport";
import type { IDBPDatabase } from 'idb';
import {
  MessageAcceptanceLookupSchema,
  SendMessageBatchResponseSchema,
  SendMessageResponseSchema,
  type MessageAcceptanceLookup,
  type SendMessageResponse,
} from '../../shared/contracts/messages';
import { apiFetch, ApiError } from '../transport/api';
import { LocalStorageError } from './errors';
import { repairSenderSequenceGap, shouldRepairSenderSequenceGap } from './sender-sequence-recovery';
import type {
  CryptoSessionEstablishmentState,
  LocalDbSchema,
  OutboxStatus,
  OutboxTransportState,
  PendingOutboxRecord,
  StaleSetType,
} from './schema';

export type OutboxTransport = {
  send: (record: PendingOutboxRecord) => Promise<SendMessageResponse>;
  lookup: (record: PendingOutboxRecord) => Promise<MessageAcceptanceLookup>;
};

type ServerCommit = Pick<SendMessageResponse, 'message_id' | 'client_message_id' | 'revision' | 'accepted_at'>;

export async function sendPendingOutboxBatch(
  db: IDBPDatabase<LocalDbSchema>,
  records: PendingOutboxRecord[],
  onChanged?: (record: PendingOutboxRecord) => void,
): Promise<PendingOutboxRecord[]> {
  if (records.length < 2) throw new Error('A message batch requires at least two records');
  const chatId = records[0]!.chat_id;
  if (records.some((record) => record.chat_id !== chatId || record.status !== 'PENDING' || record.request.attachment_ids.length > 0)) {
    throw new Error('Only pending text messages from one chat can be batched');
  }
  const response = await apiFetch(
    `/api/v1/chats/${chatId}/messages/batch`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ messages: records.map((record) => record.request) }) },
    (value) => SendMessageBatchResponseSchema.parse(value),
    { retryMode: 'idempotent' },
  );
  const commits = new Map(response.messages.map((message) => [message.client_message_id, message]));
  const committed: PendingOutboxRecord[] = [];
  for (const record of records) {
    const serverCommit = commits.get(record.client_message_id);
    if (!serverCommit) throw new LocalStorageError('CORRUPT_STATE', `Batch ACK omitted ${record.client_message_id}`);
    const updated = await transitionOutboxRecord(db, record.client_message_id, 'COMMITTED', undefined, true, undefined, serverCommit);
    if (!updated) throw new LocalStorageError('CORRUPT_STATE', `Outgoing message ${record.client_message_id} disappeared after batch ACK`);
    onChanged?.(updated);
    committed.push(updated);
  }
  return committed;
}

export type OutboxDrainResult = {
  attempted: number;
  committed: number;
  pending: number;
  failed: number;
  verify_acceptance: number;
  needs_reencrypt: number;
};

type PendingSessionResolution = 'KEEP' | 'ESTABLISH' | 'DELETE';

export function createHttpOutboxTransport(): OutboxTransport {
  return {
    async send(record) {
      return apiFetch(
        `/api/v1/chats/${record.chat_id}/messages`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': record.client_message_id,
          },
          body: JSON.stringify(await serverWireRequest(record)),
        },
        (value) => SendMessageResponseSchema.parse(value),
        { retryMode: record.request.sender_sequence === undefined ? 'idempotent' : 'ordered-message' },
      );
    },
    async lookup(record) {
      return apiFetch(
        `/api/v1/chats/${record.chat_id}/messages/by-client-id/${record.client_message_id}`,
        {},
        (value) => MessageAcceptanceLookupSchema.parse(value),
      );
    },
  };
}

/**
 * Send exactly one durable outbox record through the HTTP fallback transport.
 * No encryption occurs here; the immutable request already stored in IndexedDB
 * is retransmitted byte-for-byte at the logical JSON field level.
 */
export async function sendPendingOutboxRecord(
  db: IDBPDatabase<LocalDbSchema>,
  clientMessageId: string,
  onChanged?: (record: PendingOutboxRecord) => void,
): Promise<PendingOutboxRecord> {
  return sendPendingOutboxRecordInternal(db, clientMessageId, onChanged, true);
}

async function sendPendingOutboxRecordInternal(
  db: IDBPDatabase<LocalDbSchema>,
  clientMessageId: string,
  onChanged: ((record: PendingOutboxRecord) => void) | undefined,
  allowSequenceRepair: boolean,
): Promise<PendingOutboxRecord> {
  const transport = createHttpOutboxTransport();
  const current = await db.get('pending_outbox', clientMessageId);
  if (!current) throw new LocalStorageError('CORRUPT_STATE', `Outgoing message ${clientMessageId} disappeared before send`);
  if (current.status === 'COMMITTED' || current.status === 'FAILED' || current.status === 'NEEDS_REENCRYPT') return current;

  if (current.status === 'VERIFY_ACCEPTANCE') {
    await resolveAcceptance(db, current, transport, onChanged, current.stale_set_type);
    const after = await db.get('pending_outbox', clientMessageId);
    if (!after) throw new LocalStorageError('CORRUPT_STATE', `Outgoing message ${clientMessageId} disappeared after acceptance lookup`);
    return after;
  }

  try {
    const response = await transport.send(current);
    if (response.client_message_id !== current.client_message_id) {
      throw new LocalStorageError('CORRUPT_STATE', 'HTTP ACK client_message_id does not match durable outbox record');
    }
    const committed = await transitionOutboxRecord(db, current.client_message_id, 'COMMITTED', undefined, true, undefined, response);
    if (!committed) throw new LocalStorageError('CORRUPT_STATE', `Outgoing message ${clientMessageId} disappeared after ACK`);
    onChanged?.(committed);
    return committed;
  } catch (error) {
    if (allowSequenceRepair
      && error instanceof ApiError
      && error.type === 'SENDER_SEQUENCE_GAP'
      && error.expectedSenderSequence !== undefined
      && current.request.sender_sequence !== undefined
      && shouldRepairSenderSequenceGap(current.request.sender_sequence, error.expectedSenderSequence)) {
      try {
        const repaired = await repairSenderSequenceGap(db, current, error.expectedSenderSequence, {
          lookup: transport.lookup,
          resolveVerifyAcceptance: async (record) => {
            await resolveAcceptance(db, record, transport, onChanged, record.stale_set_type);
          },
          commitAccepted: async (record, lookup) => {
            const committed = await transitionOutboxRecord(db, record.client_message_id, 'COMMITTED', undefined, true, undefined, {
              message_id: lookup.message_id,
              client_message_id: lookup.client_message_id,
              revision: lookup.revision,
              accepted_at: lookup.accepted_at,
            });
            if (committed) onChanged?.(committed);
          },
        });
        if (repaired.repaired) {
          for (const repairedClientMessageId of repaired.ordered_client_message_ids) {
            const candidate = await db.get('pending_outbox', repairedClientMessageId);
            if (!candidate || candidate.status === 'COMMITTED' || candidate.status === 'FAILED') continue;
            if (candidate.status === 'NEEDS_REENCRYPT') break;
            const sent = await sendPendingOutboxRecordInternal(db, repairedClientMessageId, onChanged, false);
            if (sent.status !== 'COMMITTED') break;
          }
          const after = await db.get('pending_outbox', clientMessageId);
          if (!after) throw new LocalStorageError('CORRUPT_STATE', `Outgoing message ${clientMessageId} disappeared after sender sequence repair`);
          return after;
        }
      } catch {
        // Keep the same ciphertext pending. A later ordered retry can recover
        // once every ambiguous acceptance lookup is definitive.
      }
    }
    if (error instanceof ApiError && isStaleSetType(error.type)) {
      await resolveAcceptance(db, current, transport, onChanged, error.type);
      const after = await db.get('pending_outbox', clientMessageId);
      if (!after) throw new LocalStorageError('CORRUPT_STATE', `Outgoing message ${clientMessageId} disappeared after stale-set lookup`);
      return after;
    }
    const classification = classifyOutboxFailure(error);
    const updated = await transitionOutboxRecord(db, current.client_message_id, classification.status, classification.errorType, false);
    if (!updated) throw new LocalStorageError('CORRUPT_STATE', `Outgoing message ${clientMessageId} disappeared after send failure`);
    onChanged?.(updated);
    return updated;
  }
}

export async function drainPendingOutbox(
  db: IDBPDatabase<LocalDbSchema>,
  transport: OutboxTransport,
  onChanged?: (record: PendingOutboxRecord) => void,
  chatId?: string,
): Promise<OutboxDrainResult> {
  const [allPending, allVerifyAcceptance] = await Promise.all([
    db.getAllFromIndex('pending_outbox', 'by-status', 'PENDING'),
    db.getAllFromIndex('pending_outbox', 'by-status', 'VERIFY_ACCEPTANCE'),
  ]);
  const pending = chatId ? allPending.filter((record) => record.chat_id === chatId) : allPending;
  const verifyAcceptance = chatId ? allVerifyAcceptance.filter((record) => record.chat_id === chatId) : allVerifyAcceptance;
  const result: OutboxDrainResult = {
    attempted: 0,
    committed: 0,
    pending: 0,
    failed: 0,
    verify_acceptance: 0,
    needs_reencrypt: 0,
  };

  for (const record of verifyAcceptance) {
    result.attempted += 1;
    const resolved = await resolveAcceptance(db, record, transport, onChanged, record.stale_set_type);
    result[resolved] += 1;
  }

  for (const record of pending) {
    result.attempted += 1;
    try {
      const response = await transport.send(record);
      if (response.client_message_id !== record.client_message_id) throw new LocalStorageError('CORRUPT_STATE', 'HTTP ACK client_message_id mismatch');
      const committed = await transitionOutboxRecord(db, record.client_message_id, 'COMMITTED', undefined, true, undefined, response);
      if (committed) onChanged?.(committed);
      result.committed += 1;
    } catch (error) {
      if (error instanceof ApiError && isStaleSetType(error.type)) {
        const resolved = await resolveAcceptance(db, record, transport, onChanged, error.type);
        result[resolved] += 1;
        continue;
      }

      const classification = classifyOutboxFailure(error);
      const updated = await transitionOutboxRecord(db, record.client_message_id, classification.status, classification.errorType, false);
      if (updated) onChanged?.(updated);
      if (classification.status === 'PENDING') result.pending += 1;
      else if (classification.status === 'FAILED') result.failed += 1;
      else if (classification.status === 'VERIFY_ACCEPTANCE') result.verify_acceptance += 1;
      else if (classification.status === 'NEEDS_REENCRYPT') result.needs_reencrypt += 1;
    }
  }
  return result;
}

export function classifyOutboxFailure(error: unknown): { status: OutboxStatus; errorType: string } {
  if (!(error instanceof ApiError)) return { status: 'PENDING', errorType: 'NETWORK_ERROR' };
  if (error.retryable) return { status: 'PENDING', errorType: error.type };
  if (isStaleSetType(error.type)) return { status: 'VERIFY_ACCEPTANCE', errorType: error.type };
  return { status: 'FAILED', errorType: error.type };
}

export function pendingSessionResolution(status: OutboxStatus): PendingSessionResolution {
  if (status === 'COMMITTED') return 'ESTABLISH';
  if (status === 'FAILED' || status === 'NEEDS_REENCRYPT') return 'DELETE';
  return 'KEEP';
}

export async function setOutboxTransportState(
  db: IDBPDatabase<LocalDbSchema>,
  clientMessageId: string,
  transportState: OutboxTransportState,
  errorType?: string,
): Promise<PendingOutboxRecord | null> {
  const tx = db.transaction('pending_outbox', 'readwrite');
  const current = await tx.store.get(clientMessageId);
  if (!current) {
    await tx.done;
    return null;
  }
  if (current.status === 'COMMITTED' && transportState !== 'CONFIRMED') {
    await tx.done;
    return current;
  }
  const next: PendingOutboxRecord = {
    ...current,
    transport_state: transportState,
    updated_at: new Date().toISOString(),
  };
  if (errorType) next.last_error_type = errorType;
  else if (transportState !== 'RETRYING') delete next.last_error_type;
  await tx.store.put(next);
  await tx.done;
  return next;
}

export async function transitionOutboxRecord(
  db: IDBPDatabase<LocalDbSchema>,
  clientMessageId: string,
  status: OutboxStatus,
  errorType: string | undefined,
  clearRetryMaterial: boolean,
  staleSetType?: StaleSetType,
  serverCommit?: ServerCommit,
): Promise<PendingOutboxRecord | null> {
  const tx = db.transaction(['pending_outbox', 'sessions'], 'readwrite');
  const store = tx.objectStore('pending_outbox');
  const current = await store.get(clientMessageId);
  if (!current) {
    await tx.done;
    return null;
  }

  if (status === 'COMMITTED' && current.status === 'COMMITTED') {
    const alreadyComplete = !serverCommit || (
      current.server_message_id === serverCommit.message_id
      && current.server_revision === serverCommit.revision
      && current.server_accepted_at === serverCommit.accepted_at
    );
    if (alreadyComplete) {
      await tx.done;
      return current;
    }
  }

  if (serverCommit && serverCommit.client_message_id !== clientMessageId) {
    tx.abort();
    throw new LocalStorageError('CORRUPT_STATE', 'Server commit does not match local client_message_id');
  }

  const now = new Date().toISOString();
  const next: PendingOutboxRecord = {
    ...current,
    status,
    ...(status === 'COMMITTED'
      ? { transport_state: 'CONFIRMED' as const }
      : status === 'FAILED'
        ? { transport_state: 'FAILED' as const }
        : current.transport_state !== undefined
          ? { transport_state: current.transport_state }
          : {}),
    attempts: current.attempts + 1,
    updated_at: now,
    ...(serverCommit ? {
      server_message_id: serverCommit.message_id,
      server_revision: serverCommit.revision,
      server_accepted_at: serverCommit.accepted_at,
    } : {}),
  };
  if (clearRetryMaterial) delete next.encrypted_retry_material;
  if (errorType) next.last_error_type = errorType;
  else delete next.last_error_type;
  if (staleSetType) next.stale_set_type = staleSetType;
  else if (status !== 'VERIFY_ACCEPTANCE' && status !== 'NEEDS_REENCRYPT') delete next.stale_set_type;

  const resolution = pendingSessionResolution(status);
  if (resolution !== 'KEEP') {
    const sessions = tx.objectStore('sessions');
    for (const sessionId of current.pending_session_ids ?? []) {
      const session = await sessions.get(sessionId);
      if (resolution === 'ESTABLISH') {
        if (!session) {
          tx.abort();
          throw new LocalStorageError('CORRUPT_STATE', `Pending bootstrap session ${sessionId} disappeared before ACK`);
        }
        const expected: CryptoSessionEstablishmentState = 'PENDING_FIRST_MESSAGE';
        if (session.establishment_state === expected) {
          await sessions.put({ ...session, establishment_state: 'ESTABLISHED', updated_at: now });
        } else if (session.establishment_state !== 'ESTABLISHED') {
          tx.abort();
          throw new LocalStorageError('CORRUPT_STATE', `Unexpected bootstrap session state for ${sessionId}`);
        }
      } else if (session?.establishment_state === 'PENDING_FIRST_MESSAGE') {
        await sessions.delete(sessionId);
      }
    }
  }

  await store.put(next);
  await tx.done;
  return next;
}

async function resolveAcceptance(
  db: IDBPDatabase<LocalDbSchema>,
  record: PendingOutboxRecord,
  transport: OutboxTransport,
  onChanged?: (record: PendingOutboxRecord) => void,
  staleSetType?: StaleSetType,
): Promise<'committed' | 'verify_acceptance' | 'needs_reencrypt'> {
  const staleType = staleSetType ?? record.stale_set_type ?? 'RECIPIENT_SET_STALE';
  let lookup: MessageAcceptanceLookup;
  try {
    lookup = await transport.lookup(record);
  } catch {
    const verifying = await transitionOutboxRecord(
      db,
      record.client_message_id,
      'VERIFY_ACCEPTANCE',
      'ACCEPTANCE_LOOKUP_FAILED',
      false,
      staleType,
    );
    if (verifying) onChanged?.(verifying);
    return 'verify_acceptance';
  }
  if (lookup.accepted) {
    const committed = await transitionOutboxRecord(db, record.client_message_id, 'COMMITTED', undefined, true, undefined, {
      message_id: lookup.message_id,
      client_message_id: lookup.client_message_id,
      revision: lookup.revision,
      accepted_at: lookup.accepted_at,
    });
    if (committed) onChanged?.(committed);
    return 'committed';
  }
  const stale = await transitionOutboxRecord(db, record.client_message_id, 'NEEDS_REENCRYPT', staleType, false, staleType);
  if (stale) onChanged?.(stale);
  return 'needs_reencrypt';
}

function isStaleSetType(value: string): value is StaleSetType {
  return value === 'RECIPIENT_SET_STALE' || value === 'RECOVERY_SET_STALE';
}
