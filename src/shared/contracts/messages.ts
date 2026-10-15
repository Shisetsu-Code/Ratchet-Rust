import { z } from 'zod';
import { MAX_ATTACHMENTS_PER_MESSAGE } from './attachments';
import { CRYPTO_PROTOCOL, CRYPTO_PROTOCOL_VERSION } from '../constants/protocol';

export const MAX_ENCRYPTED_MESSAGE_REQUEST_BYTES = 2 * 1024 * 1024;
export const MAX_REALTIME_CLIENT_MESSAGE_BYTES = MAX_ENCRYPTED_MESSAGE_REQUEST_BYTES + 1024;
export const MAX_ENCRYPTED_HEADER_CHARS = 32 * 1024;
export const MAX_ENCRYPTED_CIPHERTEXT_CHARS = 256 * 1024;

export const DeviceEnvelopeSchema = z.object({
  recipient_user_id: z.string().uuid(),
  recipient_device_id: z.string().uuid(),
  protocol: z.literal(CRYPTO_PROTOCOL),
  protocol_version: z.literal(CRYPTO_PROTOCOL_VERSION),
  header: z.string().min(1).max(MAX_ENCRYPTED_HEADER_CHARS),
  ciphertext: z.string().min(1).max(MAX_ENCRYPTED_CIPHERTEXT_CHARS),
}).strict();

export const SendMessageRequestSchema = z.object({
  client_message_id: z.string().uuid(),
  // Optional during migration/legacy flows. The interactive streaming lane
  // always sets this and D1 enforces strict +1 progression per chat/device.
  sender_sequence: z.number().int().positive().optional(),
  // Product policy deliberately has no device-count cap. The Worker chunks
  // envelope persistence by encoded size so D1 query count does not grow one
  // statement per device. Request/body and database resource limits remain the
  // technical ceiling rather than an arbitrary account/device limit.
  envelopes: z.array(DeviceEnvelopeSchema).min(1),
  recovery_envelopes: z.array(z.object({
    recovery_key_id: z.string().min(1).max(256),
    wrapped_key: z.string().min(1).max(MAX_ENCRYPTED_HEADER_CHARS),
    archive_ciphertext: z.string().min(1).max(MAX_ENCRYPTED_CIPHERTEXT_CHARS),
  })).max(16).default([]),
  attachment_ids: z.array(z.string().uuid()).max(MAX_ATTACHMENTS_PER_MESSAGE).default([]),
  mutation: z.object({
    target_message_id: z.string().uuid(),
    type: z.enum(['EDIT', 'TOMBSTONE']),
  }).optional(),
  reply_to_message_id: z.string().uuid().optional(),
}).strict().superRefine((value, ctx) => {
  const bytes = new TextEncoder().encode(JSON.stringify(value)).byteLength;
  if (bytes > MAX_ENCRYPTED_MESSAGE_REQUEST_BYTES) {
    ctx.addIssue({ code: 'custom', message: 'Encrypted message request is too large' });
  }
});

export const SendMessageResponseSchema = z.object({
  message_id: z.string().uuid(),
  client_message_id: z.string().uuid(),
  revision: z.number().int().nonnegative(),
  accepted_at: z.string().datetime(),
  duplicate: z.boolean(),
});

export const MAX_MESSAGE_BATCH_SIZE = 10;
export const SendMessageBatchRequestSchema = z.object({
  messages: z.array(SendMessageRequestSchema).min(1).max(MAX_MESSAGE_BATCH_SIZE),
}).strict().superRefine((value, ctx) => {
  const ids = new Set<string>();
  value.messages.forEach((message, index) => {
    if (ids.has(message.client_message_id)) {
      ctx.addIssue({ code: 'custom', path: ['messages', index, 'client_message_id'], message: 'Duplicate client_message_id in batch' });
    }
    ids.add(message.client_message_id);
    if (message.attachment_ids.length > 0) {
      ctx.addIssue({ code: 'custom', path: ['messages', index, 'attachment_ids'], message: 'Attachments must be sent individually' });
    }
    if (message.mutation) ctx.addIssue({ code: 'custom', path: ['messages', index, 'mutation'], message: 'Message mutations must be sent individually' });
    if (message.reply_to_message_id) ctx.addIssue({ code: 'custom', path: ['messages', index, 'reply_to_message_id'], message: 'Replies must be sent individually' });
  });
});
export const SendMessageBatchResponseSchema = z.object({ messages: z.array(SendMessageResponseSchema) });

export const MessageAcceptanceLookupSchema = z.discriminatedUnion('accepted', [
  z.object({ accepted: z.literal(false), client_message_id: z.string().uuid() }),
  z.object({
    accepted: z.literal(true),
    message_id: z.string().uuid(),
    client_message_id: z.string().uuid(),
    revision: z.number().int().nonnegative(),
    accepted_at: z.string().datetime(),
  }),
]);

export type DeviceEnvelope = z.infer<typeof DeviceEnvelopeSchema>;
export type SendMessageRequest = z.infer<typeof SendMessageRequestSchema>;
export type SendMessageResponse = z.infer<typeof SendMessageResponseSchema>;
export type SendMessageBatchResponse = z.infer<typeof SendMessageBatchResponseSchema>;
export type MessageAcceptanceLookup = z.infer<typeof MessageAcceptanceLookupSchema>;
