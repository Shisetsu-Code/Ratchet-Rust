import { z } from 'zod';

export const ATTACHMENT_PROTOCOL_VERSION = 1 as const;
export const ATTACHMENT_CHUNK_PLAINTEXT_BYTES = 5 * 1024 * 1024;
export const ATTACHMENT_TAG_BYTES = 16;
export const MAX_ATTACHMENT_PLAINTEXT_BYTES = 10 * 1024 * 1024;
export const MAX_ATTACHMENT_PARTS = Math.max(1, Math.ceil(MAX_ATTACHMENT_PLAINTEXT_BYTES / ATTACHMENT_CHUNK_PLAINTEXT_BYTES));
export const MAX_ATTACHMENT_ENCRYPTED_BYTES = MAX_ATTACHMENT_PLAINTEXT_BYTES + MAX_ATTACHMENT_PARTS * ATTACHMENT_TAG_BYTES;
export const MAX_ATTACHMENTS_PER_MESSAGE = 16;

export const AttachmentPartSchema = z.object({
  part_number: z.number().int().min(1).max(MAX_ATTACHMENT_PARTS),
  etag: z.string().min(1).max(256),
  size: z.number().int().positive().max(ATTACHMENT_CHUNK_PLAINTEXT_BYTES + ATTACHMENT_TAG_BYTES),
});

export const ReserveAttachmentRequestSchema = z.object({
  file_id: z.string().uuid(),
  encrypted_size: z.number().int().min(ATTACHMENT_TAG_BYTES).max(MAX_ATTACHMENT_ENCRYPTED_BYTES),
  encrypted_metadata: z.string().min(1).max(16 * 1024),
});

export const ReserveAttachmentResponseSchema = z.object({
  file_id: z.string().uuid(),
  upload_id: z.string().min(1).max(512),
  status: z.literal('UPLOADING'),
  expires_at: z.string().datetime(),
  chunk_plaintext_bytes: z.literal(ATTACHMENT_CHUNK_PLAINTEXT_BYTES),
});

export const UploadAttachmentPartResponseSchema = z.object({
  part_number: z.number().int().min(1).max(MAX_ATTACHMENT_PARTS),
  etag: z.string().min(1).max(256),
  size: z.number().int().positive().max(ATTACHMENT_CHUNK_PLAINTEXT_BYTES + ATTACHMENT_TAG_BYTES),
});

export const CompleteAttachmentRequestSchema = z.object({
  parts: z.array(z.object({
    part_number: z.number().int().min(1).max(MAX_ATTACHMENT_PARTS),
    etag: z.string().min(1).max(256),
  })).min(1).max(MAX_ATTACHMENT_PARTS),
});

export const AttachmentStatusSchema = z.enum(['RESERVED','UPLOADING','READY','COMMITTED','ABORTED','EXPIRED']);
export const AttachmentStatusResponseSchema = z.object({
  file_id: z.string().uuid(),
  chat_id: z.string().uuid(),
  status: AttachmentStatusSchema,
  encrypted_size: z.number().int().nonnegative().max(MAX_ATTACHMENT_ENCRYPTED_BYTES),
  encrypted_metadata: z.string().min(1).max(16 * 1024),
  expires_at: z.string().datetime(),
  parts: z.array(AttachmentPartSchema).max(MAX_ATTACHMENT_PARTS),
});

export type AttachmentPart = z.infer<typeof AttachmentPartSchema>;
export type ReserveAttachmentRequest = z.infer<typeof ReserveAttachmentRequestSchema>;
export type ReserveAttachmentResponse = z.infer<typeof ReserveAttachmentResponseSchema>;
export type AttachmentStatusResponse = z.infer<typeof AttachmentStatusResponseSchema>;
