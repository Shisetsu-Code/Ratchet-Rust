import type { IDBPDatabase } from 'idb';
import type { AttachmentDescriptor } from './crypto';
import { uploadEncryptedAttachment } from './uploader';
import { createDecryptedAttachmentStream, getDecryptedAttachmentMetadata } from './downloader';
import { detectAllowedAttachmentType, safeAttachmentName, validateAttachmentFile, type AllowedAttachmentType } from './policy';
import { disposeDeviceIdentity, loadDeviceIdentity } from '../crypto/key-vault/identity';
import type { LocalDbSchema } from '../storage/schema';

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
};

export async function loadLocalAttachment(file: File): Promise<LoadedAttachment> {
  const type = await validateAttachmentFile(file);
  return { blob: file.slice(0, file.size, type), name: safeAttachmentName(file.name, type), type, size: file.size };
}

export async function loadDecryptedAttachment(
  chatId: string,
  descriptor: AttachmentDescriptor,
  signal?: AbortSignal,
): Promise<LoadedAttachment> {
  const metadata = await getDecryptedAttachmentMetadata(chatId, descriptor, signal);
  if (metadata.size !== descriptor.plaintext_size || metadata.size < 1) throw new Error('Decrypted attachment metadata size mismatch');
  const reader = createDecryptedAttachmentStream(chatId, descriptor, signal).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.length;
      if (total > descriptor.plaintext_size) throw new Error('Decrypted attachment exceeds its declared size');
      chunks.push(value);
    }
    if (total !== metadata.size) throw new Error('Decrypted attachment size mismatch');
    const untrustedBlob = new Blob(chunks.map((chunk) => chunk.slice().buffer), { type: 'application/octet-stream' });
    const detectedType = await detectAllowedAttachmentType(untrustedBlob);
    if (!detectedType || detectedType !== metadata.type) throw new Error('Attachment content does not match its encrypted file type');
    return {
      blob: untrustedBlob.slice(0, untrustedBlob.size, detectedType),
      name: safeAttachmentName(metadata.name, detectedType),
      type: detectedType,
      size: total,
    };
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    await reader.cancel().catch(() => undefined);
  }
}

export function downloadLoadedAttachment(attachment: LoadedAttachment): void {
  const url = URL.createObjectURL(attachment.blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = attachment.name;
  anchor.rel = 'noopener';
  anchor.hidden = true;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

export async function downloadAttachmentToFile(
  chatId: string,
  descriptor: AttachmentDescriptor,
): Promise<void> {
  downloadLoadedAttachment(await loadDecryptedAttachment(chatId, descriptor));
}
