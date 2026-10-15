import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { CRYPTO_PROFILE_V1 } from './profile';

export class CryptoPrimitiveError extends Error {}

export type AeadSealed = { nonce: Uint8Array; ciphertext: Uint8Array };
export type MlKemKeyPair = { publicKey: Uint8Array; secretKey: Uint8Array };
export type MlKemEncapsulation = { cipherText: Uint8Array; sharedSecret: Uint8Array };

export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length <= 0) throw new CryptoPrimitiveError('Random byte length must be a positive safe integer');
  return crypto.getRandomValues(new Uint8Array(length));
}

export function sha256Digest(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function sha512Digest(data: Uint8Array): Uint8Array {
  return sha512(data);
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length <= 0) throw new CryptoPrimitiveError('HKDF output length must be a positive safe integer');
  return hkdf(sha256, ikm, salt, info, length);
}

export function hkdfSha512(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length <= 0) throw new CryptoPrimitiveError('HKDF output length must be a positive safe integer');
  return hkdf(sha512, ikm, salt, info, length);
}

export function x25519PublicKey(secretKey: Uint8Array): Uint8Array {
  exactLength(secretKey, 32, 'X25519 secret key');
  return x25519.getPublicKey(secretKey);
}

export function x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  exactLength(secretKey, 32, 'X25519 secret key');
  exactLength(peerPublicKey, 32, 'X25519 public key');
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(secretKey, peerPublicKey);
  } catch (error) {
    throw new CryptoPrimitiveError(`X25519 rejected peer key: ${error instanceof Error ? error.message : 'invalid key'}`);
  }
  if (shared.every((byte) => byte === 0)) throw new CryptoPrimitiveError('X25519 produced an all-zero shared secret');
  return shared;
}

export function xchachaSeal(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  nonce: Uint8Array = randomBytes(CRYPTO_PROFILE_V1.nonceLength),
): AeadSealed {
  exactLength(key, CRYPTO_PROFILE_V1.messageKeyLength, 'XChaCha20-Poly1305 key');
  exactLength(nonce, CRYPTO_PROFILE_V1.nonceLength, 'XChaCha20-Poly1305 nonce');
  const cipher = xchacha20poly1305(key, nonce, aad);
  return { nonce: nonce.slice(), ciphertext: cipher.encrypt(plaintext) };
}

export function xchachaOpen(key: Uint8Array, sealed: AeadSealed, aad: Uint8Array): Uint8Array {
  exactLength(key, CRYPTO_PROFILE_V1.messageKeyLength, 'XChaCha20-Poly1305 key');
  exactLength(sealed.nonce, CRYPTO_PROFILE_V1.nonceLength, 'XChaCha20-Poly1305 nonce');
  try {
    return xchacha20poly1305(key, sealed.nonce, aad).decrypt(sealed.ciphertext);
  } catch {
    throw new CryptoPrimitiveError('XChaCha20-Poly1305 authentication failed');
  }
}

export function mlKem1024Keygen(seed?: Uint8Array): MlKemKeyPair {
  if (seed) exactLength(seed, 64, 'ML-KEM-1024 keygen seed');
  const pair = seed ? ml_kem1024.keygen(seed) : ml_kem1024.keygen();
  return { publicKey: pair.publicKey, secretKey: pair.secretKey };
}

export function mlKem1024Encapsulate(publicKey: Uint8Array, randomness?: Uint8Array): MlKemEncapsulation {
  exactLength(publicKey, CRYPTO_PROFILE_V1.mlKem1024PublicKeyLength, 'ML-KEM-1024 public key');
  if (randomness) exactLength(randomness, 32, 'ML-KEM-1024 encapsulation randomness');
  const result = randomness ? ml_kem1024.encapsulate(publicKey, randomness) : ml_kem1024.encapsulate(publicKey);
  return { cipherText: result.cipherText, sharedSecret: result.sharedSecret };
}

export function mlKem1024Decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  exactLength(cipherText, CRYPTO_PROFILE_V1.mlKem1024CiphertextLength, 'ML-KEM-1024 ciphertext');
  exactLength(secretKey, CRYPTO_PROFILE_V1.mlKem1024SecretKeyLength, 'ML-KEM-1024 secret key');
  return ml_kem1024.decapsulate(cipherText, secretKey);
}

export function wipe(...buffers: Uint8Array[]): void {
  for (const buffer of buffers) buffer.fill(0);
}

function exactLength(value: Uint8Array, expected: number, label: string): void {
  if (value.length !== expected) throw new CryptoPrimitiveError(`${label} must be ${expected} bytes`);
}
