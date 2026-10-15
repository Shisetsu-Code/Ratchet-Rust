import type { IDBPDatabase } from 'idb';
import type { MessageAcceptanceLookup } from '../../shared/contracts/messages';
import { apiFetch } from '../transport/api';
import type { LocalDbSchema, PendingOutboxRecord } from './schema';
import { senderSequenceSettingKey } from './sender-sequence';

export type SenderSequenceRecoveryHooks = {
  lookup: (record: PendingOutboxRecord) => Promise<MessageAcceptanceLookup>;
  resolveVerifyAcceptance: (record: PendingOutboxRecord) => Promise<void>;
  commitAccepted: (record: PendingOutboxRecord, lookup: Extract<MessageAcceptanceLookup, { accepted: true }>) => Promise<void>;
};

export type SenderSequenceRecoveryResult =
  | { repaired: false; ordered_client_message_ids: [] }
  | { repaired: true; ordered_client_message_ids: string[] };

export function shouldRepairSenderSequenceGap(localSequence: number, expectedSequence: number): boolean {
  return Number.isSafeInteger(localSequence)
    && Number.isSafeInteger(expectedSequence)
    && localSequence > 0
    && expectedSequence > localSequence;
}

export async function repairSenderSequenceGap(
  db: IDBPDatabase<LocalDbSchema>,
  triggeringRecord: PendingOutboxRecord,
  expectedSequence: number,
  hooks: SenderSequenceRecoveryHooks,
): Promise<SenderSequenceRecoveryResult> {
  const triggeringSequence = triggeringRecord.request.sender_sequence;
  if (triggeringSequence === undefined || !shouldRepairSenderSequenceGap(triggeringSequence, expectedSequence)) {
    return { repaired: false, ordered_client_message_ids: [] };
  }

  const before = (await db.getAllFromIndex('pending_outbox', 'by-chat', triggeringRecord.chat_id))
    .filter((record) => record.sender_device_id === triggeringRecord.sender_device_id && isSequenceRepairCandidate(record))
    .sort(compareSenderSequenceRecords);

  // Never rewrite another request while its old sender_sequence can still
  // commit after the acceptance lookup.
  if (before.some((record) => record.client_message_id !== triggeringRecord.client_message_id
    && senderSequenceTransportInFlight(record))) {
    return { repaired: false, ordered_client_message_ids: [] };
  }

  for (const record of before) {
    if (record.status === 'NEEDS_REENCRYPT') continue;
    if (record.status === 'VERIFY_ACCEPTANCE') {
      await hooks.resolveVerifyAcceptance(record);
      continue;
    }
    const lookup = await hooks.lookup(record);
    if (lookup.accepted) await hooks.commitAccepted(record, lookup);
  }

  // Re-read D1 after acceptance resolution. This is the only sequence value
  // trusted for renumbering the still-unaccepted local suffix.
  const remote = await apiFetch(
    `/api/v1/chats/${encodeURIComponent(triggeringRecord.chat_id)}/messages/sender-sequence`,
    {},
    (value) => {
      const next = (value as { next_sequence?: unknown } | null)?.next_sequence;
      if (!Number.isSafeInteger(next) || (next as number) <= 0) throw new Error('Invalid authoritative sender sequence');
      return { next_sequence: next as number };
    },
  );

  const fresh = (await db.getAllFromIndex('pending_outbox', 'by-chat', triggeringRecord.chat_id))
    .filter((record) => record.sender_device_id === triggeringRecord.sender_device_id && isSequenceRepairCandidate(record))
    .sort(compareSenderSequenceRecords);
  if (fresh.some((record) => record.status === 'VERIFY_ACCEPTANCE'
    || (record.attempts > 0 && record.request.sender_sequence! >= remote.next_sequence))) {
    return { repaired: false, ordered_client_message_ids: [] };
  }
  if (fresh.some((record) => record.client_message_id !== triggeringRecord.client_message_id
    && senderSequenceTransportInFlight(record))) {
    return { repaired: false, ordered_client_message_ids: [] };
  }

  const tx = db.transaction(['pending_outbox', 'settings'], 'readwrite');
  const outboxStore = tx.objectStore('pending_outbox');
  const settings = tx.objectStore('settings');
  let nextSequence = remote.next_sequence;
  const orderedClientMessageIds: string[] = [];

  for (const snapshot of fresh) {
    const stored = await outboxStore.get(snapshot.client_message_id);
    if (!stored || JSON.stringify(stored) !== JSON.stringify(snapshot)
      || stored.status === 'VERIFY_ACCEPTANCE' || !isSequenceRepairCandidate(stored)
      || (stored.client_message_id !== triggeringRecord.client_message_id && senderSequenceTransportInFlight(stored))) {
      tx.abort();
      await tx.done.catch(() => undefined);
      return { repaired: false, ordered_client_message_ids: [] };
    }
    await outboxStore.put({
      ...stored,
      request: { ...stored.request, sender_sequence: nextSequence },
      transport_state: 'RETRYING',
      last_error_type: 'SENDER_SEQUENCE_REPAIRED',
      updated_at: new Date().toISOString(),
    });
    orderedClientMessageIds.push(stored.client_message_id);
    nextSequence += 1;
  }

  await settings.put({
    key: senderSequenceSettingKey(triggeringRecord.chat_id, triggeringRecord.sender_device_id),
    kind: 'json',
    value: { version: 1, last_allocated: nextSequence - 1 },
  });
  await tx.done;
  return { repaired: true, ordered_client_message_ids: orderedClientMessageIds };
}

function isSequenceRepairCandidate(record: PendingOutboxRecord): boolean {
  return record.request.sender_sequence !== undefined
    && (record.status === 'PENDING' || record.status === 'VERIFY_ACCEPTANCE' || record.status === 'NEEDS_REENCRYPT');
}

function senderSequenceTransportInFlight(record: PendingOutboxRecord): boolean {
  return record.transport_state === 'WS_IN_FLIGHT' || record.transport_state === 'HTTP_FALLBACK_IN_FLIGHT';
}

function compareSenderSequenceRecords(left: PendingOutboxRecord, right: PendingOutboxRecord): number {
  return (left.request.sender_sequence! - right.request.sender_sequence!)
    || left.created_at.localeCompare(right.created_at)
    || left.client_message_id.localeCompare(right.client_message_id);
}
