const text = new TextEncoder();

export const CRYPTO_PROFILE_V1 = Object.freeze({
  protocol: 'secure-messaging' as const,
  version: 1 as const,
  curve: 'X25519' as const,
  pqKem: 'ML-KEM-1024' as const,
  pqxdhHash: 'SHA-512' as const,
  ratchetHash: 'SHA-256' as const,
  aead: 'XChaCha20-Poly1305' as const,
  x25519PublicKeyLength: 32 as const,
  mlKem1024PublicKeyLength: 1568 as const,
  mlKem1024SecretKeyLength: 3168 as const,
  mlKem1024CiphertextLength: 1568 as const,
  mlKemSharedSecretLength: 32 as const,
  messageKeyLength: 32 as const,
  nonceLength: 24 as const,
  tagLength: 16 as const,
  maxSkip: 2_000 as const,
});

// Signal's PQXDH encoding requirement is range separation, not these exact values.
// These prefixes therefore define this application's v1 wire profile and are not a
// claim of byte-for-byte Signal interoperability.
export const ENCODE_EC_PREFIX_V1 = 0x05 as const;
export const ENCODE_KEM_PREFIX_V1 = 0x06 as const;

export const PQXDH_INFO_BASE_V1 = text.encode('RatchetSecureSupport/PQXDH/v1');
export const RATCHET_ROOT_INFO_V1 = text.encode('RatchetSecureSupport/DoubleRatchet/root/v1');
export const MESSAGE_AEAD_INFO_V1 = text.encode('RatchetSecureSupport/DoubleRatchet/message/v1');
export const CHAIN_MESSAGE_CONSTANT_V1 = new Uint8Array([0x01]);
export const CHAIN_NEXT_CONSTANT_V1 = new Uint8Array([0x02]);
