import type { IDBPDatabase } from 'idb';
import type { AttachmentDescriptor } from './crypto';
import { uploadEncryptedAttachment } from './uploader';
import { createDecryptedAttachmentStream, getDecryptedAttachmentMetadata } from './downloader';
import { detectAllowedAttachmentType, safeAttachmentName, validateAttachmentFile, type AllowedAttachmentType } from './policy';
import { disposeDeviceIdentity, loadDeviceIdentity } from '../crypto/key-vault/identity';
import type { LocalDbSchema } from '../storage/schema';
import { attachmentResources } from './resource-budget';
import { inspectImagePreview, type ImagePreviewPolicy } from './preview-policy';

export async function uploadAttachmentForMessage(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  chatId: string,
  file: File,
  onProgress?: (percent: number) => void,
): Promise<AttachmentDescriptor> {
  const identity = await loadDeviceIdentity(db, deviceId);
  try {
    return await uploadEncryptedAttachment(db, identity.masterKey, chatId, file, onProgress);
  } finally {
    disposeDeviceIdentity(identity);
  }
}

export type LoadedAttachment = {
  blob: Blob;
  name: string;
  type: AllowedAttachmentType;
  size: number;
  preview: ImagePreviewPolicy;
  release: () => void;
};

export async function loadLocalAttachment(file: File, signal?: AbortSignal): Promise<LoadedAttachment> {
  const release = await attachmentResources.reserve(Math.max(1, file.size * 3), signal);
  try {
    signal?.throwIfAborted();
    const type = await validateAttachmentFile(file);
    const blob = file.slice(0, file.size, type);
    const preview = await inspectImagePreview(blob, type);
    signal?.throwIfAborted();
    return { blob, name: safeAttachmentName(file.name, type), type, size: file.size, preview, release };
  } catch (error) { release(); throw error; }
}

export async function loadDecryptedAttachment(
  chatId: string,
  descriptor: AttachmentDescriptor,
  signal?: AbortSignal,
): Promise<LoadedAttachment> {
  const release = await attachmentResources.reserve(Math.max(1, descriptor.plaintext_size * 3), signal);
  try { return await loadReservedAttachment(chatId, descriptor, release, signal); }
  catch (error) { release(); throw error; }
}

async function loadReservedAttachment(chatId: string, descriptor: AttachmentDescriptor, release: () => void, signal?: AbortSignal): Promise<LoadedAttachment> {
  signal?.throwIfAborted();
  const metadata = await getDecryptedAttachmentMetadata(chatId, descriptor, signal);
  if (metadata.size !== descriptor.plaintext_size || metadata.size < 1) throw new Error('Decrypted attachment metadata size mismatch');
  const reader = createDecryptedAttachmentStream(chatId, descriptor, signal).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      signal?.throwIfAborted();
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.length;
      if (total > descriptor.plaintext_size) throw new Error('Decrypted attachment exceeds its declared size');
      if (chunks.length === 0 && await detectAllowedAttachmentType(new Blob([value.slice(0, 16).buffer])) !== metadata.type) {
        value.fill(0);
        throw new Error('Attachment content does not match its encrypted file type');
      }
      chunks.push(value);
    }
    if (total !== metadata.size) throw new Error('Decrypted attachment size mismatch');
    const untrustedBlob = new Blob(chunks as Uint8Array<ArrayBuffer>[], { type: 'application/octet-stream' });
    const detectedType = await detectAllowedAttachmentType(untrustedBlob);
    if (!detectedType || detectedType !== metadata.type) throw new Error('Attachment content does not match its encrypted file type');
    const preview = await inspectImagePreview(untrustedBlob, detectedType);
    signal?.throwIfAborted();
    return {
      blob: untrustedBlob.slice(0, untrustedBlob.size, detectedType),
      name: safeAttachmentName(metadata.name, detectedType),
      type: detectedType,
      size: total,
      preview, release,
    };
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    await reader.cancel().catch(() => undefined);
  }
}

export async function downloadLoadedAttachment(attachment: LoadedAttachment): Promise<void> {
  const url = URL.createObjectURL(attachment.blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = attachment.name;
  anchor.rel = 'noopener';
  anchor.hidden = true;
  try {
    document.body.append(anchor);
    anchor.click();
    await new Promise(resolve => window.setTimeout(resolve, 1_000));
  } finally {
    anchor.remove();
    URL.revokeObjectURL(url);
  }
}

export async function downloadAttachmentToFile(
  chatId: string,
  descriptor: AttachmentDescriptor,
): Promise<void> {
  const attachment = await loadDecryptedAttachment(chatId, descriptor);
  try { await downloadLoadedAttachment(attachment); }
  finally { attachment.release(); }
}
