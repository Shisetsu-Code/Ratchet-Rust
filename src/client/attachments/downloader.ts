import { ATTACHMENT_CHUNK_PLAINTEXT_BYTES, ATTACHMENT_TAG_BYTES, MAX_ATTACHMENT_PLAINTEXT_BYTES } from '../../shared/contracts/attachments';
import { base64UrlToBytes } from '../crypto/local-state/base64url';
import { wipe } from '../crypto/primitives';
import { readResponseBytes } from '../transport/bounded-bytes';
import { getAttachmentStatusHttp } from './api';
import { attachmentPartCount, decryptAttachmentMetadata, decryptAttachmentPart, type AttachmentDescriptor } from './crypto';

export async function getDecryptedAttachmentMetadata(chatId: string, descriptor: AttachmentDescriptor, signal?: AbortSignal) {
  assertSafeDescriptor(descriptor);
  const status = await getAttachmentStatusHttp(descriptor.file_id, signal);
  if (status.status !== 'COMMITTED') throw new Error('Attachment is not committed');
  if (status.chat_id !== chatId) throw new Error('Attachment belongs to another chat');
  if (status.encrypted_size !== descriptor.plaintext_size + attachmentPartCount(descriptor.plaintext_size) * ATTACHMENT_TAG_BYTES) {
    throw new Error('Attachment encrypted size does not match its descriptor');
  }
  const key = base64UrlToBytes(descriptor.file_key);
  try { return decryptAttachmentMetadata(chatId, descriptor.file_id, key, status.encrypted_metadata); }
  finally { wipe(key); }
}

export function createDecryptedAttachmentStream(chatId: string, descriptor: AttachmentDescriptor, signal?: AbortSignal): ReadableStream<Uint8Array> {
  assertSafeDescriptor(descriptor);
  const abort = new AbortController();
  const forwardAbort = () => abort.abort(signal?.reason);
  if (signal?.aborted) forwardAbort();
  else signal?.addEventListener('abort', forwardAbort, { once: true });
  const cleanup = () => signal?.removeEventListener('abort', forwardAbort);
  let cancelled = false;
  let partNumber = 1;
  const partCount = attachmentPartCount(descriptor.plaintext_size);
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (partNumber > partCount) {
        cleanup();
        controller.close();
        return;
      }
      try {
        abort.signal.throwIfAborted();
        const fullCipherChunk = ATTACHMENT_CHUNK_PLAINTEXT_BYTES + ATTACHMENT_TAG_BYTES;
        const start = (partNumber - 1) * fullCipherChunk;
        const plaintextLength = partNumber < partCount
          ? ATTACHMENT_CHUNK_PLAINTEXT_BYTES
          : descriptor.plaintext_size - ATTACHMENT_CHUNK_PLAINTEXT_BYTES * (partCount - 1);
        const ciphertextLength = plaintextLength + ATTACHMENT_TAG_BYTES;
        const end = start + ciphertextLength - 1;
        const response = await fetch(`/api/v1/attachments/${descriptor.file_id}/content`, {
          credentials: 'same-origin',
          headers: { Range: `bytes=${start}-${end}` },
          signal: abort.signal,
        });
        if (response.status !== 206 && !(partCount === 1 && response.status === 200)) throw new Error(`Attachment range download failed (${response.status})`);
        const ciphertext = await readResponseBytes(response, ciphertextLength);
        if (ciphertext.length !== ciphertextLength) throw new Error('Attachment range length mismatch');
        try {
          abort.signal.throwIfAborted();
          const plaintext = decryptAttachmentPart(chatId, descriptor, partNumber, ciphertext);
          controller.enqueue(plaintext);
        } finally {
          wipe(ciphertext);
        }
        partNumber += 1;
      } catch (error) {
        cleanup();
        if (!cancelled) controller.error(error);
      }
    },
    cancel(reason) {
      cancelled = true;
      abort.abort(reason);
      cleanup();
    },
  }, { highWaterMark: 0 });
}

function assertSafeDescriptor(descriptor: AttachmentDescriptor): void {
  if (
    descriptor.version !== 1
    || descriptor.chunk_plaintext_bytes !== ATTACHMENT_CHUNK_PLAINTEXT_BYTES
    || !Number.isSafeInteger(descriptor.plaintext_size)
    || descriptor.plaintext_size < 1
    || descriptor.plaintext_size > MAX_ATTACHMENT_PLAINTEXT_BYTES
    || !/^[A-Za-z0-9_-]{43}$/.test(descriptor.file_key)
    || !/^[A-Za-z0-9_-]{22}$/.test(descriptor.nonce_prefix)
  ) throw new Error('Attachment descriptor is invalid');
}
