import { ed25519 } from '@noble/curves/ed25519.js';
import { z } from 'zod';
import { portableKeySignatureMessage, type PortableKeyChallengeResponse } from '../../shared/contracts/portable-keys';
import { uuidv7 } from '../../shared/ids/uuidv7';
import { base64UrlToBytes, bytesToBase64Url } from '../crypto/local-state/base64url';
import { wipe } from '../crypto/primitives';

const ITERATIONS = 600_000;
const MAX_FILE_BYTES = 64 * 1024;
const FileSchema = z.object({
  format: z.literal('ratchet-portable-key'),
  version: z.literal(1),
  key_id: z.string().uuid(),
  public_key: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  kdf: z.object({ name: z.literal('PBKDF2-SHA256'), iterations: z.number().int().min(600_000).max(5_000_000), salt: z.string().regex(/^[A-Za-z0-9_-]{22}$/) }),
  cipher: z.object({ name: z.literal('AES-256-GCM'), iv: z.string().regex(/^[A-Za-z0-9_-]{16}$/), ciphertext: z.string().min(64).max(4096).regex(/^[A-Za-z0-9_-]+$/) }),
});
type PortableKeyFile = z.infer<typeof FileSchema>;

export type UnlockedPortableKey = { keyId: string; publicKey: string; privateSeed: Uint8Array };

export async function createPortableKeyFile(password: string): Promise<{ fileName: string; contents: string; unlocked: UnlockedPortableKey }> {
  const privateSeed = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = bytesToBase64Url(ed25519.getPublicKey(privateSeed));
  const keyId = uuidv7();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const metadata = {
    format: 'ratchet-portable-key' as const, version: 1 as const, key_id: keyId, public_key: publicKey,
    kdf: { name: 'PBKDF2-SHA256' as const, iterations: ITERATIONS, salt: bytesToBase64Url(salt) },
    cipher: { name: 'AES-256-GCM' as const, iv: bytesToBase64Url(iv) },
  };
  const plaintext = new TextEncoder().encode(JSON.stringify({ private_seed: bytesToBase64Url(privateSeed), public_key: publicKey }));
  try {
    const key = await deriveFileKey(password, salt, ITERATIONS);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: arrayBuffer(iv), additionalData: arrayBuffer(aad(metadata)) }, key, arrayBuffer(plaintext),
    ));
    const document = { ...metadata, cipher: { ...metadata.cipher, ciphertext: bytesToBase64Url(ciphertext) } };
    return { fileName: `ratchet-${keyId}.ratchet-key`, contents: `${JSON.stringify(document, null, 2)}\n`, unlocked: { keyId, publicKey, privateSeed } };
  } catch (error) {
    wipe(privateSeed);
    throw error;
  } finally {
    wipe(plaintext, salt, iv);
  }
}

export async function unlockPortableKey(file: File, password: string): Promise<UnlockedPortableKey> {
  if (file.size <= 0 || file.size > MAX_FILE_BYTES) throw new Error('El archivo de llave está vacío o supera 64 KiB.');
  let parsed: PortableKeyFile;
  try { parsed = FileSchema.parse(JSON.parse(await file.text())); }
  catch { throw new Error('El archivo no tiene un formato .ratchet-key válido.'); }
  const salt = base64UrlToBytes(parsed.kdf.salt);
  const iv = base64UrlToBytes(parsed.cipher.iv);
  const ciphertext = base64UrlToBytes(parsed.cipher.ciphertext);
  let plaintext: Uint8Array | null = null;
  try {
    const key = await deriveFileKey(password, salt, parsed.kdf.iterations);
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: arrayBuffer(iv), additionalData: arrayBuffer(aad({ ...parsed, cipher: { name: parsed.cipher.name, iv: parsed.cipher.iv } })) }, key, arrayBuffer(ciphertext),
    ));
    const inner = z.object({ private_seed: z.string().regex(/^[A-Za-z0-9_-]{43}$/), public_key: z.string() }).parse(JSON.parse(new TextDecoder().decode(plaintext)));
    const privateSeed = base64UrlToBytes(inner.private_seed);
    const derivedPublicKey = bytesToBase64Url(ed25519.getPublicKey(privateSeed));
    if (inner.public_key !== parsed.public_key || derivedPublicKey !== parsed.public_key) {
      wipe(privateSeed);
      throw new Error('key mismatch');
    }
    return { keyId: parsed.key_id, publicKey: parsed.public_key, privateSeed };
  } catch {
    throw new Error('No se pudo descifrar la llave. Revisá la contraseña y el archivo.');
  } finally {
    wipe(salt, iv, ciphertext);
    if (plaintext) wipe(plaintext);
  }
}

export function signPortableChallenge(key: UnlockedPortableKey, challenge: PortableKeyChallengeResponse): string {
  if (challenge.key_id !== key.keyId) throw new Error('El desafío no corresponde a este archivo de llave.');
  return bytesToBase64Url(ed25519.sign(portableKeySignatureMessage({
    purpose: challenge.purpose, challenge_id: challenge.challenge_id, challenge: challenge.challenge,
    origin: challenge.origin, key_id: challenge.key_id,
  }), key.privateSeed));
}

export function disposePortableKey(key: UnlockedPortableKey): void { wipe(key.privateSeed); }

export function downloadPortableKey(fileName: string, contents: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: 'application/json' }));
  const anchor = document.createElement('a');
  try { anchor.href = url; anchor.download = fileName; anchor.click(); }
  finally { setTimeout(() => URL.revokeObjectURL(url), 0); }
}

async function deriveFileKey(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: arrayBuffer(salt), iterations }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function aad(metadata: { format: string; version: number; key_id: string; public_key: string; kdf: { name: string; iterations: number; salt: string }; cipher: { name: string; iv: string } }): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    format: metadata.format, version: metadata.version, key_id: metadata.key_id, public_key: metadata.public_key,
    kdf: metadata.kdf, cipher: metadata.cipher,
  }));
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
