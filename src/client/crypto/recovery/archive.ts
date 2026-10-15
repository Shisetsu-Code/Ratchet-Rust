import { concatBytes, utf8 } from '../encoding';
import { base64UrlToBytes, bytesToBase64Url } from '../local-state/base64url';
import { randomBytes, wipe, x25519PublicKey, x25519SharedSecret } from '../primitives';
import { validateMessageSemantics, type MessageSemantics } from '../../chat/content';
import { xed25519Sign, xed25519Verify } from '../xeddsa';

const ARCHIVE_PROTOCOL = 'secure-recovery-archive' as const;
const WRAP_PROTOCOL = 'secure-recovery-key-wrap' as const;
const RECOVERY_VERSION = 1 as const;
const AES_KEY_LENGTH = 32;
const AES_GCM_NONCE_LENGTH = 12;
const HKDF_SALT_LENGTH = 32;
const X25519_KEY_LENGTH = 32;

const ARCHIVE_AAD_DOMAIN = utf8('RatchetSecureSupport/recovery-archive/v1');
const WRAP_AAD_DOMAIN = utf8('RatchetSecureSupport/recovery-key-wrap/v1');
const WRAP_KDF_DOMAIN = utf8('RatchetSecureSupport/recovery-wrap-kdf/v1');
const SIGNED_ARCHIVE_DOMAIN = utf8('RatchetSecureSupport/signed-recovery-content/v1\u0000');

export type RecoveryRecipient = {
  recovery_key_id: string;
  public_key: Uint8Array;
};

export type RecoveryArchiveEnvelope = {
  recovery_key_id: string;
  wrapped_key: string;
  archive_ciphertext: string;
};

type ArchiveWire = {
  protocol: typeof ARCHIVE_PROTOCOL;
  version: typeof RECOVERY_VERSION;
  nonce: string;
  ciphertext: string;
};

type WrappedKeyWire = {
  protocol: typeof WRAP_PROTOCOL;
  version: typeof RECOVERY_VERSION;
  ephemeral_public_key: string;
  salt: string;
  nonce: string;
  ciphertext: string;
};

export async function createRecoveryArchive(
  plaintext: Uint8Array,
  recipients: readonly RecoveryRecipient[],
): Promise<RecoveryArchiveEnvelope[]> {
  const ordered = normalizeRecipients(recipients);
  if (ordered.length === 0) return [];

  const archiveMessageKey = randomBytes(AES_KEY_LENGTH);
  let archiveCiphertext: string;
  try {
    archiveCiphertext = await encryptArchivePayload(archiveMessageKey, plaintext);
    const envelopes: RecoveryArchiveEnvelope[] = [];
    for (const recipient of ordered) {
      envelopes.push({
        recovery_key_id: recipient.recovery_key_id,
        wrapped_key: await wrapArchiveMessageKey(archiveMessageKey, recipient),
        archive_ciphertext: archiveCiphertext,
      });
    }
    return envelopes;
  } finally {
    wipe(archiveMessageKey);
  }
}

export async function decryptRecoveryArchive(
  envelope: RecoveryArchiveEnvelope,
  recoveryPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  requireLength(recoveryPrivateKey, X25519_KEY_LENGTH, 'recovery private key');
  const archiveMessageKey = await unwrapArchiveMessageKey(envelope.wrapped_key, envelope.recovery_key_id, recoveryPrivateKey);
  try {
    return await decryptArchivePayload(archiveMessageKey, envelope.archive_ciphertext);
  } finally {
    wipe(archiveMessageKey);
  }
}

export function generateRecoveryKeyPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = randomBytes(X25519_KEY_LENGTH);
  return { privateKey, publicKey: x25519PublicKey(privateKey) };
}

export async function decryptBoundRecoveryArchive(
  envelope: RecoveryArchiveEnvelope,
  recoveryPrivateKey: Uint8Array,
  metadata: MessageSemantics,
  trustedSenderPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const signed = await decryptRecoveryArchive(envelope, recoveryPrivateKey);
  let plaintext: Uint8Array | undefined;
  let signature: Uint8Array | undefined;
  let signingBytes: Uint8Array | undefined;
  try {
    const wire: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(signed));
    if (!isRecord(wire) || wire.protocol !== 'signed-recovery-content' || wire.version !== 1
      || typeof wire.content !== 'string' || typeof wire.signature !== 'string') {
      throw new Error('Recovery archive requires signed content');
    }
    plaintext = base64UrlToBytes(wire.content);
    signature = base64UrlToBytes(wire.signature);
    signingBytes = concatBytes(SIGNED_ARCHIVE_DOMAIN, plaintext);
    if (!await xed25519Verify(trustedSenderPublicKey, signingBytes, signature)) {
      throw new Error('Recovery sender signature verification failed');
    }
    // Recovery has no ratchet session to supply the missing identity/context.
    // Require an authenticated frame even for historical unbound archives.
    validateMessageSemantics(plaintext, metadata);
    validateMessageSemantics(plaintext, { ...metadata, protocol_version: 2 });
    return plaintext;
  } catch (error) {
    if (plaintext) wipe(plaintext);
    throw error;
  } finally {
    wipe(signed);
    if (signature) wipe(signature);
    if (signingBytes) wipe(signingBytes);
  }
}

export async function createSignedRecoveryArchive(
  plaintext: Uint8Array,
  recipients: readonly RecoveryRecipient[],
  senderPrivateKey: Uint8Array,
): Promise<RecoveryArchiveEnvelope[]> {
  if (recipients.length === 0) return [];
  const signingBytes = concatBytes(SIGNED_ARCHIVE_DOMAIN, plaintext);
  let signature: Uint8Array | undefined;
  let signed: Uint8Array | undefined;
  try {
    signature = await xed25519Sign(senderPrivateKey, signingBytes);
    signed = utf8(JSON.stringify({ protocol: 'signed-recovery-content', version: 1,
      content: bytesToBase64Url(plaintext), signature: bytesToBase64Url(signature) }));
    return await createRecoveryArchive(signed, recipients);
  } finally {
    wipe(signingBytes);
    if (signature) wipe(signature);
    if (signed) wipe(signed);
  }
}

async function encryptArchivePayload(archiveMessageKey: Uint8Array, plaintext: Uint8Array): Promise<string> {
  const nonce = randomBytes(AES_GCM_NONCE_LENGTH);
  try {
    const ciphertext = await aesGcmEncrypt(archiveMessageKey, nonce, plaintext, ARCHIVE_AAD_DOMAIN);
    return encodeWire<ArchiveWire>({
      protocol: ARCHIVE_PROTOCOL,
      version: RECOVERY_VERSION,
      nonce: bytesToBase64Url(nonce),
      ciphertext: bytesToBase64Url(ciphertext),
    });
  } finally {
    wipe(nonce);
  }
}

async function decryptArchivePayload(archiveMessageKey: Uint8Array, encoded: string): Promise<Uint8Array> {
  const wire = decodeArchiveWire(encoded);
  const nonce = base64UrlToBytes(wire.nonce);
  const ciphertext = base64UrlToBytes(wire.ciphertext);
  try {
    requireLength(nonce, AES_GCM_NONCE_LENGTH, 'archive nonce');
    return await aesGcmDecrypt(archiveMessageKey, nonce, ciphertext, ARCHIVE_AAD_DOMAIN);
  } finally {
    wipe(nonce, ciphertext);
  }
}

async function wrapArchiveMessageKey(
  archiveMessageKey: Uint8Array,
  recipient: RecoveryRecipient,
): Promise<string> {
  requireLength(recipient.public_key, X25519_KEY_LENGTH, 'recovery public key');
  const ephemeralPrivateKey = randomBytes(X25519_KEY_LENGTH);
  const ephemeralPublicKey = x25519PublicKey(ephemeralPrivateKey);
  const sharedSecret = x25519SharedSecret(ephemeralPrivateKey, recipient.public_key);
  const salt = randomBytes(HKDF_SALT_LENGTH);
  const nonce = randomBytes(AES_GCM_NONCE_LENGTH);
  let wrappingKey: Uint8Array | undefined;
  try {
    wrappingKey = await deriveWrappingKey(sharedSecret, salt, recipient.recovery_key_id);
    const aad = wrappingAad(recipient.recovery_key_id, ephemeralPublicKey);
    const ciphertext = await aesGcmEncrypt(wrappingKey, nonce, archiveMessageKey, aad);
    return encodeWire<WrappedKeyWire>({
      protocol: WRAP_PROTOCOL,
      version: RECOVERY_VERSION,
      ephemeral_public_key: bytesToBase64Url(ephemeralPublicKey),
      salt: bytesToBase64Url(salt),
      nonce: bytesToBase64Url(nonce),
      ciphertext: bytesToBase64Url(ciphertext),
    });
  } finally {
    wipe(ephemeralPrivateKey, ephemeralPublicKey, sharedSecret, salt, nonce);
    if (wrappingKey) wipe(wrappingKey);
  }
}

async function unwrapArchiveMessageKey(
  encoded: string,
  recoveryKeyId: string,
  recoveryPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  const wire = decodeWrappedKeyWire(encoded);
  const ephemeralPublicKey = base64UrlToBytes(wire.ephemeral_public_key);
  const salt = base64UrlToBytes(wire.salt);
  const nonce = base64UrlToBytes(wire.nonce);
  const ciphertext = base64UrlToBytes(wire.ciphertext);
  requireLength(ephemeralPublicKey, X25519_KEY_LENGTH, 'ephemeral recovery public key');
  requireLength(salt, HKDF_SALT_LENGTH, 'recovery HKDF salt');
  requireLength(nonce, AES_GCM_NONCE_LENGTH, 'recovery wrap nonce');

  const sharedSecret = x25519SharedSecret(recoveryPrivateKey, ephemeralPublicKey);
  let wrappingKey: Uint8Array | undefined;
  try {
    wrappingKey = await deriveWrappingKey(sharedSecret, salt, recoveryKeyId);
    const aad = wrappingAad(recoveryKeyId, ephemeralPublicKey);
    const archiveMessageKey = await aesGcmDecrypt(wrappingKey, nonce, ciphertext, aad);
    requireLength(archiveMessageKey, AES_KEY_LENGTH, 'archive message key');
    return archiveMessageKey;
  } finally {
    wipe(ephemeralPublicKey, salt, nonce, ciphertext, sharedSecret);
    if (wrappingKey) wipe(wrappingKey);
  }
}

async function deriveWrappingKey(sharedSecret: Uint8Array, salt: Uint8Array, recoveryKeyId: string): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey('raw', toBuffer(sharedSecret), 'HKDF', false, ['deriveBits']);
  const info = concatBytes(WRAP_KDF_DOMAIN, lengthPrefixed(utf8(recoveryKeyId)));
  try {
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: toBuffer(salt), info: toBuffer(info) },
      keyMaterial,
      AES_KEY_LENGTH * 8,
    );
    return new Uint8Array(bits);
  } finally {
    wipe(info);
  }
}

async function aesGcmEncrypt(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  requireLength(keyBytes, AES_KEY_LENGTH, 'AES-256 key');
  const key = await crypto.subtle.importKey('raw', toBuffer(keyBytes), 'AES-GCM', false, ['encrypt']);
  const result = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBuffer(nonce), additionalData: toBuffer(aad), tagLength: 128 },
    key,
    toBuffer(plaintext),
  );
  return new Uint8Array(result);
}

async function aesGcmDecrypt(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  requireLength(keyBytes, AES_KEY_LENGTH, 'AES-256 key');
  const key = await crypto.subtle.importKey('raw', toBuffer(keyBytes), 'AES-GCM', false, ['decrypt']);
  try {
    const result = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toBuffer(nonce), additionalData: toBuffer(aad), tagLength: 128 },
      key,
      toBuffer(ciphertext),
    );
    return new Uint8Array(result);
  } catch (error) {
    throw new Error('Recovery archive authentication failed', { cause: error });
  }
}

function normalizeRecipients(recipients: readonly RecoveryRecipient[]): RecoveryRecipient[] {
  const ids = new Set<string>();
  return recipients
    .map((recipient) => {
      if (!recipient.recovery_key_id) throw new Error('Recovery key ID is required');
      if (ids.has(recipient.recovery_key_id)) throw new Error(`Duplicate recovery key ID ${recipient.recovery_key_id}`);
      ids.add(recipient.recovery_key_id);
      requireLength(recipient.public_key, X25519_KEY_LENGTH, 'recovery public key');
      return { recovery_key_id: recipient.recovery_key_id, public_key: recipient.public_key.slice() };
    })
    .sort((left, right) => left.recovery_key_id.localeCompare(right.recovery_key_id));
}

function wrappingAad(recoveryKeyId: string, ephemeralPublicKey: Uint8Array): Uint8Array {
  return concatBytes(
    WRAP_AAD_DOMAIN,
    lengthPrefixed(utf8(recoveryKeyId)),
    lengthPrefixed(ephemeralPublicKey),
  );
}

function lengthPrefixed(value: Uint8Array): Uint8Array {
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, value.length, false);
  return concatBytes(length, value);
}

function encodeWire<T>(value: T): string {
  return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function decodeArchiveWire(encoded: string): ArchiveWire {
  const value = decodeJson(encoded);
  if (!isRecord(value) || value.protocol !== ARCHIVE_PROTOCOL || value.version !== RECOVERY_VERSION) {
    throw new Error('Unsupported recovery archive format');
  }
  if (typeof value.nonce !== 'string' || typeof value.ciphertext !== 'string') {
    throw new Error('Malformed recovery archive');
  }
  return value as ArchiveWire;
}

function decodeWrappedKeyWire(encoded: string): WrappedKeyWire {
  const value = decodeJson(encoded);
  if (!isRecord(value) || value.protocol !== WRAP_PROTOCOL || value.version !== RECOVERY_VERSION) {
    throw new Error('Unsupported recovery key wrapper');
  }
  if (
    typeof value.ephemeral_public_key !== 'string'
    || typeof value.salt !== 'string'
    || typeof value.nonce !== 'string'
    || typeof value.ciphertext !== 'string'
  ) {
    throw new Error('Malformed recovery key wrapper');
  }
  return value as WrappedKeyWire;
}

function decodeJson(encoded: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(encoded))) as unknown;
  } catch (error) {
    throw new Error('Malformed recovery envelope encoding', { cause: error });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireLength(value: Uint8Array, expected: number, label: string): void {
  if (value.length !== expected) throw new Error(`${label} must be ${expected} bytes`);
}

function toBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer as ArrayBuffer;
}
