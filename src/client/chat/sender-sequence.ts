import type { IDBPDatabase } from 'idb';
import { z } from 'zod';
import { apiFetch } from '../transport/api';
import type { JsonSetting, LocalDbSchema } from '../storage/schema';
import { parseSenderSequenceState, senderSequenceSettingKey } from '../storage/sender-sequence';

const SenderSequenceResponseSchema = z.object({ next_sequence: z.number().int().positive() });

/**
 * Seed the durable local allocator from D1 once. The actual +1 allocation is
 * performed later inside the same IndexedDB transaction that commits ratchet
 * state + outbox, so a crash cannot consume a sequence without a durable
 * message.
 */
export async function ensureSenderSequenceSeed(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  senderDeviceId: string,
): Promise<void> {
  const key = senderSequenceSettingKey(chatId, senderDeviceId);
  const existing = await db.get('settings', key);
  if (existing?.kind === 'json' && parseSenderSequenceState(existing.value)) return;

  const remote = await apiFetch(
    `/api/v1/chats/${encodeURIComponent(chatId)}/messages/sender-sequence`,
    {},
    (value) => SenderSequenceResponseSchema.parse(value),
  );

  const tx = db.transaction('settings', 'readwrite');
  const current = await tx.store.get(key);
  if (!(current?.kind === 'json' && parseSenderSequenceState(current.value))) {
    await tx.store.put({
      key,
      kind: 'json',
      value: { version: 1, last_allocated: remote.next_sequence - 1 },
    } satisfies JsonSetting);
  }
  await tx.done;
}
