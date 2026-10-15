import type { IDBPDatabase } from 'idb';
import { sha256Digest, wipe } from '../crypto/primitives';
import { bytesToBase64Url, base64UrlToBytes } from '../crypto/local-state/base64url';
import { wrapLocalSecret, unwrapLocalSecret } from '../crypto/local-state/wrapping';
import { utf8 } from '../crypto/encoding';
import { uuidv7 } from '../../shared/ids/uuidv7';
import { ATTACHMENT_CHUNK_PLAINTEXT_BYTES, MAX_ATTACHMENT_PLAINTEXT_BYTES } from '../../shared/contracts/attachments';
import type { AttachmentUploadRecord, LocalDbSchema } from '../storage/schema';
import { completeAttachmentHttp, getAttachmentStatusHttp, reserveAttachmentHttp, uploadAttachmentPartHttp } from './api';
import {
  attachmentPartCount,
  createAttachmentSecrets,
  descriptorForAttachment,
  encryptedAttachmentSize,
  encryptAttachmentMetadata,
  encryptAttachmentPart,
  type AttachmentDescriptor,
} from './crypto';
import { validateAttachmentFile } from './policy';

export async function uploadEncryptedAttachment(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  chatId: string,
  file: File,
  onProgress?: (percent: number) => void,
): Promise<AttachmentDescriptor> {
  onProgress?.(0);
  if (file.size > MAX_ATTACHMENT_PLAINTEXT_BYTES) throw new Error('El archivo supera el límite de 10 MB.');
  const detectedType = await validateAttachmentFile(file);
  const fileId = uuidv7();
  const secrets = createAttachmentSecrets(fileId, file.size);
  try {
    const encryptedMetadata = encryptAttachmentMetadata(chatId, fileId, secrets.fileKey, {
      name: file.name,
      type: detectedType,
      size: file.size,
      last_modified: file.lastModified,
    });
    const reserve = await reserveAttachmentHttp(chatId, {
      file_id: fileId,
      encrypted_size: encryptedAttachmentSize(file.size),
      encrypted_metadata: encryptedMetadata,
    });
    const wrapped = await wrapLocalSecret(masterKey, secrets.fileKey, attachmentKeyAad(chatId, fileId));
    const record: AttachmentUploadRecord = {
      file_id: fileId,
      chat_id: chatId,
      status: 'UPLOADING',
      upload_id: reserve.upload_id,
      object_key: '',
      next_part_number: 1,
      etags: {},
      encrypted_file_key: wrapped.ciphertext,
      file_key_nonce: wrapped.nonce,
      nonce_prefix: bytesToBase64Url(secrets.noncePrefix),
      plaintext_size: file.size,
      chunk_plaintext_bytes: ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
      encrypted_metadata: encryptedMetadata,
      source_fingerprint: sourceFingerprint(file),
      updated_at: new Date().toISOString(),
    };
    await db.put('attachment_uploads', record);
    await uploadRemaining(db, file, record, secrets.fileKey, secrets.noncePrefix, onProgress);
    const completed = await completeFromServerState(db, record);
    await db.put('attachment_uploads', { ...record, status: completed.status, updated_at: new Date().toISOString() });
    onProgress?.(100);
    return descriptorForAttachment(fileId, secrets.fileKey, secrets.noncePrefix, file.size);
  } finally {
    wipe(secrets.fileKey, secrets.noncePrefix);
  }
}

export async function resumeEncryptedAttachment(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  fileId: string,
  file: File,
): Promise<AttachmentDescriptor> {
  await validateAttachmentFile(file);
  const record = await db.get('attachment_uploads', fileId);
  if (!record) throw new Error('Local attachment upload state is missing');
  if (record.source_fingerprint !== sourceFingerprint(file) || record.plaintext_size !== file.size) throw new Error('Selected file does not match resumable attachment state');
  const fileKey = await unwrapLocalSecret(masterKey, { nonce: record.file_key_nonce, ciphertext: record.encrypted_file_key }, attachmentKeyAad(record.chat_id, fileId));
  const noncePrefix = base64UrlToBytes(record.nonce_prefix);
  try {
    const server = await getAttachmentStatusHttp(fileId);
    if (server.status === 'READY' || server.status === 'COMMITTED') {
      return descriptorForAttachment(fileId, fileKey, noncePrefix, record.plaintext_size);
    }
    if (server.status !== 'UPLOADING') throw new Error(`Attachment cannot resume from ${server.status}`);
    record.etags = Object.fromEntries(server.parts.map((part) => [String(part.part_number), part.etag]));
    await uploadRemaining(db, file, record, fileKey, noncePrefix);
    const completed = await completeFromServerState(db, record);
    await db.put('attachment_uploads', { ...record, status: completed.status, updated_at: new Date().toISOString() });
    return descriptorForAttachment(fileId, fileKey, noncePrefix, record.plaintext_size);
  } finally {
    wipe(fileKey, noncePrefix);
  }
}

async function uploadRemaining(
  db: IDBPDatabase<LocalDbSchema>,
  file: File,
  record: AttachmentUploadRecord,
  fileKey: Uint8Array,
  noncePrefix: Uint8Array,
  onProgress?: (percent: number) => void,
): Promise<void> {
  const count = attachmentPartCount(file.size);
  for (let partNumber = 1; partNumber <= count; partNumber += 1) {
    if (record.etags[String(partNumber)]) continue;
    const start = (partNumber - 1) * ATTACHMENT_CHUNK_PLAINTEXT_BYTES;
    const end = Math.min(file.size, start + ATTACHMENT_CHUNK_PLAINTEXT_BYTES);
    const plaintext = new Uint8Array(await file.slice(start, end).arrayBuffer());
    const ciphertext = encryptAttachmentPart(record.chat_id, record.file_id, fileKey, noncePrefix, file.size, partNumber, plaintext);
    wipe(plaintext);
    const uploaded = await uploadAttachmentPartHttp(record.file_id, partNumber, ciphertext);
    wipe(ciphertext);
    record.etags[String(partNumber)] = uploaded.etag;
    record.next_part_number = partNumber + 1;
    record.updated_at = new Date().toISOString();
    await db.put('attachment_uploads', { ...record });
    onProgress?.(Math.round((partNumber / count) * 95));
  }
}

async function completeFromServerState(db: IDBPDatabase<LocalDbSchema>, record: AttachmentUploadRecord) {
  const server = await getAttachmentStatusHttp(record.file_id);
  const parts = server.parts.map((part) => ({ part_number: part.part_number, etag: part.etag }));
  if (parts.length === 0) throw new Error('Server has no uploaded attachment parts');
  record.etags = Object.fromEntries(parts.map((part) => [String(part.part_number), part.etag]));
  await db.put('attachment_uploads', { ...record, updated_at: new Date().toISOString() });
  return completeAttachmentHttp(record.file_id, parts);
}

function sourceFingerprint(file: File): string {
  return bytesToBase64Url(sha256Digest(utf8(`${file.name}\u0000${file.type}\u0000${file.size}\u0000${file.lastModified}`)));
}

function attachmentKeyAad(chatId: string, fileId: string): Uint8Array {
  return utf8(`RatchetSecureSupport/local-attachment-key/v1\u0000${chatId}\u0000${fileId}`);
}
