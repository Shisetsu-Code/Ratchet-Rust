import { z } from 'zod';
import { DeviceEnvelopeSchema, SendMessageRequestSchema, SendMessageResponseSchema } from './messages';

export const RealtimePingSchema = z.object({
  type: z.literal('ping'),
  after_revision: z.number().int().nonnegative(),
});

export const RealtimeSendMessageSchema = z.object({
  type: z.literal('message.send'),
  request: SendMessageRequestSchema,
});

export const RealtimeClientMessageSchema = z.discriminatedUnion('type', [
  RealtimePingSchema,
  RealtimeSendMessageSchema,
]);

export const RealtimeMessageAckSchema = SendMessageResponseSchema.extend({
  type: z.literal('message.ack'),
  chat_id: z.string().uuid(),
});

export const RealtimeCommittedMessageSchema = z.object({
  type: z.literal('message.committed'),
  chat_id: z.string().uuid(),
  message_id: z.string().uuid(),
  client_message_id: z.string().uuid(),
  sender_user_id: z.string().uuid(),
  sender_device_id: z.string().uuid(),
  sender_display_name: z.string().trim().min(1).max(80).nullable().optional(),
  sender_sequence: z.number().int().positive().optional(),
  revision: z.number().int().positive(),
  accepted_at: z.string().datetime(),
  mutation: z.object({ target_message_id: z.string().uuid(), type: z.enum(['EDIT', 'TOMBSTONE']) }).nullable().default(null),
  reply_to_message_id: z.string().uuid().nullable().default(null),
  envelope: DeviceEnvelopeSchema,
});

export const RealtimeMessageNackSchema = z.object({
  type: z.literal('message.nack'),
  chat_id: z.string().uuid(),
  client_message_id: z.string().uuid(),
  error_type: z.string().min(1).max(96),
  retryable: z.boolean(),
});

export const RealtimeServerEventSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('receipt.committed'), chat_id: z.string().uuid(), revision: z.number().int().positive(), message_id: z.string().uuid(), user_id: z.string().uuid(), state: z.enum(['READ', 'DELIVERED']) }),
  z.object({ type: z.literal('realtime.ready'), chat_id: z.string().uuid(), revision: z.number().int().nonnegative() }),
  z.object({ type: z.literal('chat.changed'), chat_id: z.string().uuid(), revision: z.number().int().nonnegative() }),
  z.object({ type: z.literal('sync.required'), chat_id: z.string().uuid(), revision: z.number().int().nonnegative() }),
  z.object({ type: z.literal('pong'), chat_id: z.string().uuid(), revision: z.number().int().nonnegative() }),
  z.object({ type: z.literal('presence.changed'), chat_id: z.string().uuid(), online_user_ids: z.array(z.string().uuid()).max(256), observed_at: z.string().datetime() }),
  RealtimeMessageAckSchema,
  RealtimeCommittedMessageSchema,
  RealtimeMessageNackSchema,
]);

export type RealtimeClientMessage = z.infer<typeof RealtimeClientMessageSchema>;
export type RealtimeServerEvent = z.infer<typeof RealtimeServerEventSchema>;
export type RealtimeMessageAck = z.infer<typeof RealtimeMessageAckSchema>;
export type RealtimeCommittedMessage = z.infer<typeof RealtimeCommittedMessageSchema>;
