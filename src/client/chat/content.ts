import { z } from 'zod';
import { ATTACHMENT_CHUNK_PLAINTEXT_BYTES, ATTACHMENT_PROTOCOL_VERSION, MAX_ATTACHMENT_PLAINTEXT_BYTES } from '../../shared/contracts/attachments';
import type { AttachmentDescriptor } from '../attachments/crypto';

const AttachmentDescriptorSchema = z.object({
  version: z.literal(ATTACHMENT_PROTOCOL_VERSION),
  file_id: z.string().uuid(),
  file_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  nonce_prefix: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  plaintext_size: z.number().int().min(1).max(MAX_ATTACHMENT_PLAINTEXT_BYTES),
  chunk_plaintext_bytes: z.literal(ATTACHMENT_CHUNK_PLAINTEXT_BYTES),
});

const MessageContentSchema = z.object({
  v: z.literal(1),
  text: z.string().max(200_000),
  attachments: z.array(AttachmentDescriptorSchema).max(16),
});

export type MessageContent = {
  v: 1;
  text: string;
  attachments: AttachmentDescriptor[];
};

const AuthenticatedMessageContentSchema = z.object({
  protocol: z.literal('secure-message-content'),
  v: z.literal(2),
  chat_id: z.string().min(1),
  client_message_id: z.string().min(1),
  sender_user_id: z.string().min(1),
  sender_device_id: z.string().min(1),
  message_type: z.enum(['MESSAGE', 'EDIT', 'TOMBSTONE']),
  mutation: z.object({ type: z.enum(['EDIT', 'TOMBSTONE']), target_message_id: z.string().min(1) }).strict().nullable(),
  reply_to_message_id: z.string().min(1).nullable(),
  text: z.string().max(200_000),
  attachments: z.array(AttachmentDescriptorSchema).max(16),
}).strict();
export type AuthenticatedMessageContent = z.infer<typeof AuthenticatedMessageContentSchema>;
export type MessageSemantics = Pick<AuthenticatedMessageContent, 'chat_id' | 'client_message_id' | 'sender_user_id' | 'sender_device_id'> & {
  mutation?: AuthenticatedMessageContent['mutation'] | undefined;
  reply_to_message_id?: string | null | undefined;
  protocol_version?: number | undefined;
};
export class MessageSemanticsError extends Error {}

export function frameAuthenticatedMessageContent(plaintext: Uint8Array, metadata: MessageSemantics): Uint8Array {
  const content = decodeMessageContent(plaintext);
  if (content.v === 2) {
    validateMessageSemantics(plaintext, metadata);
    return plaintext;
  }
  return new TextEncoder().encode(JSON.stringify(AuthenticatedMessageContentSchema.parse({
    protocol: 'secure-message-content', v: 2,
    chat_id: metadata.chat_id, client_message_id: metadata.client_message_id,
    sender_user_id: metadata.sender_user_id, sender_device_id: metadata.sender_device_id,
    message_type: metadata.mutation?.type ?? 'MESSAGE', mutation: metadata.mutation ?? null,
    reply_to_message_id: metadata.reply_to_message_id ?? null, text: content.text, attachments: content.attachments,
  })));
}

export function validateMessageSemantics(plaintext: Uint8Array, metadata: MessageSemantics) {
  const content = decodeMessageContent(plaintext);
  // Historical plaintext is readable, but never authorizes edits, deletions or replies.
  if (content.v !== 2) {
    if (metadata.protocol_version === 2) throw new MessageSemanticsError('Protocol v2 requires authenticated content');
    return { mutation: null, reply_to_message_id: null };
  }
  if (metadata.protocol_version !== undefined && metadata.protocol_version !== 2) throw new MessageSemanticsError('Authenticated protocol version mismatch');
  if (content.chat_id !== metadata.chat_id || content.client_message_id !== metadata.client_message_id
    || content.sender_user_id !== metadata.sender_user_id || content.sender_device_id !== metadata.sender_device_id
    || content.message_type !== (metadata.mutation?.type ?? 'MESSAGE')
    || content.mutation?.type !== metadata.mutation?.type
    || content.mutation?.target_message_id !== metadata.mutation?.target_message_id
    || content.reply_to_message_id !== (metadata.reply_to_message_id ?? null)) {
    throw new MessageSemanticsError('Delivery metadata differs from authenticated message semantics');
  }
  return { mutation: content.mutation, reply_to_message_id: content.reply_to_message_id };
}

export function encodeMessageContent(text: string, attachments: readonly AttachmentDescriptor[] = []): Uint8Array {
  const content: MessageContent = { v: 1, text, attachments: [...attachments] };
  return new TextEncoder().encode(JSON.stringify(MessageContentSchema.parse(content)));
}

export function decodeMessageContent(plaintext: Uint8Array): MessageContent | AuthenticatedMessageContent {
  const decoded = new TextDecoder().decode(plaintext);
  let value: unknown;
  try {
    value = JSON.parse(decoded) as unknown;
  } catch {
    // Historical v0 messages were raw UTF-8 text.
    return { v: 1, text: decoded, attachments: [] };
  }
  if (typeof value === 'object' && value !== null && ('v' in value && value.v === 2 || 'protocol' in value && value.protocol === 'secure-message-content')) {
    const framed = AuthenticatedMessageContentSchema.safeParse(value);
    if (!framed.success) throw new MessageSemanticsError('Invalid authenticated message framing');
    return framed.data;
  }
  const parsed = MessageContentSchema.safeParse(value);
  if (parsed.success) return parsed.data;
  return { v: 1, text: decoded, attachments: [] };
}
