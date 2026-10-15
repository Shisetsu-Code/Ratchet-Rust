import {
  CRYPTO_PROFILE_V1,
  ENCODE_EC_PREFIX_V1,
  ENCODE_KEM_PREFIX_V1,
} from './profile';

export class CryptoEncodingError extends Error {}

export function encodeX25519PublicKey(publicKey: Uint8Array): Uint8Array {
  exactLength(publicKey, CRYPTO_PROFILE_V1.x25519PublicKeyLength, 'X25519 public key');
  const out = new Uint8Array(1 + publicKey.length);
  out[0] = ENCODE_EC_PREFIX_V1;
  out.set(publicKey, 1);
  return out;
}

export function decodeX25519PublicKey(encoded: Uint8Array): Uint8Array {
  exactLength(encoded, 1 + CRYPTO_PROFILE_V1.x25519PublicKeyLength, 'encoded X25519 public key');
  if (encoded[0] !== ENCODE_EC_PREFIX_V1) throw new CryptoEncodingError('Unexpected EC key encoding prefix');
  return encoded.slice(1);
}

export function encodeMlKem1024PublicKey(publicKey: Uint8Array): Uint8Array {
  exactLength(publicKey, CRYPTO_PROFILE_V1.mlKem1024PublicKeyLength, 'ML-KEM-1024 public key');
  const out = new Uint8Array(1 + publicKey.length);
  out[0] = ENCODE_KEM_PREFIX_V1;
  out.set(publicKey, 1);
  return out;
}

export function decodeMlKem1024PublicKey(encoded: Uint8Array): Uint8Array {
  exactLength(encoded, 1 + CRYPTO_PROFILE_V1.mlKem1024PublicKeyLength, 'encoded ML-KEM-1024 public key');
  if (encoded[0] !== ENCODE_KEM_PREFIX_V1) throw new CryptoEncodingError('Unexpected KEM key encoding prefix');
  return encoded.slice(1);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function exactLength(value: Uint8Array, expected: number, label: string): void {
  if (value.length !== expected) throw new CryptoEncodingError(`${label} must be ${expected} bytes`);
}
