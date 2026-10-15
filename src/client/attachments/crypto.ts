import { ATTACHMENT_CHUNK_PLAINTEXT_BYTES, ATTACHMENT_PROTOCOL_VERSION, ATTACHMENT_TAG_BYTES } from '../../shared/contracts/attachments';
import { concatBytes, utf8 } from '../crypto/encoding';
import { base64UrlToBytes, bytesToBase64Url } from '../crypto/local-state/base64url';
import { randomBytes, wipe, xchachaOpen, xchachaSeal } from '../crypto/primitives';

const NONCE_PREFIX_BYTES = 16;
const NONCE_BYTES = 24;
const DOMAIN = utf8('RatchetSecureSupport/attachment/v1');
const META_DOMAIN = utf8('RatchetSecureSupport/attachment-metadata/v1');

export type AttachmentPlainMetadata = {
  name: string;
  type: string;
  size: number;
  last_modified: number;
};

export type AttachmentDescriptor = {
  version: 1;
  file_id: string;
  file_key: string;
  nonce_prefix: string;
  plaintext_size: number;
  chunk_plaintext_bytes: number;
};

export function createAttachmentSecrets(fileId: string, plaintextSize: number) {
  if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0) throw new Error('Invalid attachment plaintext size');
  return {
    fileId,
    fileKey: randomBytes(32),
    noncePrefix: randomBytes(NONCE_PREFIX_BYTES),
    plaintextSize,
  };
}

export function attachmentPartCount(plaintextSize: number): number {
  return Math.max(1, Math.ceil(plaintextSize / ATTACHMENT_CHUNK_PLAINTEXT_BYTES));
}

export function encryptedAttachmentSize(plaintextSize: number): number {
  return plaintextSize + attachmentPartCount(plaintextSize) * ATTACHMENT_TAG_BYTES;
}

export function encryptAttachmentPart(
  chatId: string,
  fileId: string,
  fileKey: Uint8Array,
  noncePrefix: Uint8Array,
  plaintextSize: number,
  partNumber: number,
  plaintext: Uint8Array,
): Uint8Array {
  const nonce = partNonce(noncePrefix, partNumber);
  return xchachaSeal(fileKey, plaintext, partAad(chatId, fileId, plaintextSize, partNumber), nonce).ciphertext;
}

export function decryptAttachmentPart(
  chatId: string,
  descriptor: AttachmentDescriptor,
  partNumber: number,
  ciphertext: Uint8Array,
): Uint8Array {
  if (descriptor.version !== ATTACHMENT_PROTOCOL_VERSION || descriptor.chunk_plaintext_bytes !== ATTACHMENT_CHUNK_PLAINTEXT_BYTES) {
    throw new Error('Unsupported attachment descriptor');
  }
  const key = base64UrlToBytes(descriptor.file_key);
  const prefix = base64UrlToBytes(descriptor.nonce_prefix);
  const nonce = partNonce(prefix, partNumber);
  try {
    return xchachaOpen(key, { nonce, ciphertext }, partAad(chatId, descriptor.file_id, descriptor.plaintext_size, partNumber));
  } finally {
    wipe(key, prefix, nonce);
  }
}

export function encryptAttachmentMetadata(
  chatId: string,
  fileId: string,
  fileKey: Uint8Array,
  metadata: AttachmentPlainMetadata,
): string {
  const encoded = utf8(JSON.stringify(metadata));
  const sealed = xchachaSeal(fileKey, encoded, metadataAad(chatId, fileId));
  const packed = concatBytes(sealed.nonce, sealed.ciphertext);
  try { return bytesToBase64Url(packed); }
  finally { wipe(encoded, sealed.nonce, sealed.ciphertext, packed); }
}

export function decryptAttachmentMetadata(chatId: string, fileId: string, fileKey: Uint8Array, packed: string): AttachmentPlainMetadata {
  const bytes = base64UrlToBytes(packed);
  if (bytes.length <= NONCE_BYTES) throw new Error('Encrypted attachment metadata is truncated');
  const nonce = bytes.slice(0, NONCE_BYTES);
  const ciphertext = bytes.slice(NONCE_BYTES);
  let plaintext: Uint8Array | null = null;
  try {
    plaintext = xchachaOpen(fileKey, { nonce, ciphertext }, metadataAad(chatId, fileId));
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    if (!parsed || typeof parsed !== 'object') throw new Error('Attachment metadata is invalid');
    const value = parsed as Record<string, unknown>;
    if (typeof value.name !== 'string' || typeof value.type !== 'string' || !Number.isSafeInteger(value.size) || !Number.isSafeInteger(value.last_modified)) {
      throw new Error('Attachment metadata fields are invalid');
    }
    return { name: value.name, type: value.type, size: value.size as number, last_modified: value.last_modified as number };
  } finally {
    wipe(bytes, nonce, ciphertext);
    if (plaintext) wipe(plaintext);
  }
}

export function descriptorForAttachment(fileId: string, fileKey: Uint8Array, noncePrefix: Uint8Array, plaintextSize: number): AttachmentDescriptor {
  return {
    version: ATTACHMENT_PROTOCOL_VERSION,
    file_id: fileId,
    file_key: bytesToBase64Url(fileKey),
    nonce_prefix: bytesToBase64Url(noncePrefix),
    plaintext_size: plaintextSize,
    chunk_plaintext_bytes: ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  };
}

function partNonce(prefix: Uint8Array, partNumber: number): Uint8Array {
  if (prefix.length !== NONCE_PREFIX_BYTES) throw new Error('Attachment nonce prefix must be 16 bytes');
  if (!Number.isSafeInteger(partNumber) || partNumber < 1) throw new Error('Invalid attachment part number');
  const suffix = new Uint8Array(8);
  new DataView(suffix.buffer).setBigUint64(0, BigInt(partNumber), false);
  return concatBytes(prefix, suffix);
}

function partAad(chatId: string, fileId: string, plaintextSize: number, partNumber: number): Uint8Array {
  return concatBytes(DOMAIN, field(chatId), field(fileId), u64(plaintextSize), u64(partNumber));
}

function metadataAad(chatId: string, fileId: string): Uint8Array {
  return concatBytes(META_DOMAIN, field(chatId), field(fileId));
}

function field(value: string): Uint8Array {
  const encoded = utf8(value);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, encoded.length, false);
  return concatBytes(length, encoded);
}

function u64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}
