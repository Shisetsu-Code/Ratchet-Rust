import { z } from 'zod';

export const SyncCursorSchema = z.coerce.number().int().nonnegative().default(0);

export const ChatChangedEventSchema = z.object({
  type: z.literal('chat.changed'),
  chat_id: z.string().uuid(),
  revision: z.number().int().nonnegative(),
});

export const SyncMessageChangeSchema = z.object({
  type: z.literal('message'),
  revision: z.number().int().nonnegative(),
  message_id: z.string().uuid(),
  sender_user_id: z.string().uuid(),
  sender_device_id: z.string().uuid(),
  sender_display_name: z.string().trim().min(1).max(80).nullable(),
  client_message_id: z.string().uuid(),
  protocol: z.string(),
  protocol_version: z.number().int().positive(),
  created_at: z.string(),
  mutation: z.object({ target_message_id: z.string().uuid(), type: z.enum(['EDIT', 'TOMBSTONE']) }).nullable().default(null),
  reply_to_message_id: z.string().uuid().nullable().default(null),
  envelope: z.object({
    header: z.string(),
    ciphertext: z.string(),
  }).nullable(),
});

export const SyncReceiptChangeSchema = z.object({
  type: z.literal('receipt'),
  revision: z.number().int().nonnegative(),
  message_id: z.string().uuid(),
  user_id: z.string().uuid(),
  state: z.enum(['DELIVERED', 'READ']),
  updated_at: z.string(),
});

export const SyncChangeSchema = z.discriminatedUnion('type', [SyncMessageChangeSchema, SyncReceiptChangeSchema]);
export const ChatSyncResponseSchema = z.object({
  chat_id: z.string().uuid(),
  revision: z.number().int().nonnegative(),
  sender_profiles: z.array(z.object({ sender_user_id: z.string().uuid(), display_name: z.string().trim().min(1).max(80) })),
  changes: z.array(SyncChangeSchema),
  next_revision: z.number().int().nonnegative(),
  has_more: z.boolean(),
});
