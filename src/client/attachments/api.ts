import {
  AttachmentStatusResponseSchema,
  CompleteAttachmentRequestSchema,
  ReserveAttachmentResponseSchema,
  UploadAttachmentPartResponseSchema,
  type AttachmentStatusResponse,
} from '../../shared/contracts/attachments';
import { apiFetch } from '../transport/api';

export async function reserveAttachmentHttp(chatId: string, input: { file_id: string; encrypted_size: number; encrypted_metadata: string }) {
  return apiFetch(`/api/v1/chats/${chatId}/attachments`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
  }, (value) => ReserveAttachmentResponseSchema.parse(value), { retryMode: 'idempotent' });
}

export async function uploadAttachmentPartHttp(fileId: string, partNumber: number, ciphertext: Uint8Array) {
  return apiFetch(`/api/v1/attachments/${fileId}/parts/${partNumber}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream', 'X-Encrypted-Part-Size': String(ciphertext.length) },
    body: ciphertext.slice().buffer,
  }, (value) => UploadAttachmentPartResponseSchema.parse(value), { retryMode: 'upload-part', timeoutMs: 30_000 });
}

export async function completeAttachmentHttp(fileId: string, parts: Array<{ part_number: number; etag: string }>): Promise<AttachmentStatusResponse> {
  const body = CompleteAttachmentRequestSchema.parse({ parts });
  return apiFetch(`/api/v1/attachments/${fileId}/complete`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }, (value) => AttachmentStatusResponseSchema.parse(value), { retryMode: 'idempotent' });
}

export async function getAttachmentStatusHttp(fileId: string, signal?: AbortSignal): Promise<AttachmentStatusResponse> {
  return apiFetch(`/api/v1/attachments/${fileId}`, signal ? { signal } : {}, (value) => AttachmentStatusResponseSchema.parse(value));
}

export async function abortAttachmentHttp(fileId: string): Promise<void> {
  await apiFetch(`/api/v1/attachments/${fileId}`, { method: 'DELETE' }, () => undefined, { retryMode: 'idempotent' });
}
