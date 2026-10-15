import { concatBytes, encodeX25519PublicKey, utf8 } from '../encoding';
import { hkdfSha512 } from '../primitives';

const HASH_LEN = 64;
const OUTPUT_LEN = 32;
const F = new Uint8Array(32).fill(0xff);
const ZERO_SALT = new Uint8Array(HASH_LEN);

export const PQXDH_INFO_V1 = utf8(
  'RatchetSecureSupport_CURVE_X25519_HASH_SHA-512_PQKEM_ML-KEM-1024',
);

export function derivePqXdhSharedSecret(keyMaterial: Uint8Array): Uint8Array {
  return hkdfSha512(concatBytes(F, keyMaterial), ZERO_SALT, PQXDH_INFO_V1, OUTPUT_LEN);
}

export function pqXdhAssociatedData(
  initiatorIdentityPublicKey: Uint8Array,
  responderIdentityPublicKey: Uint8Array,
): Uint8Array {
  return concatBytes(
    encodeX25519PublicKey(initiatorIdentityPublicKey),
    encodeX25519PublicKey(responderIdentityPublicKey),
  );
}
