import { concatBytes } from '../encoding';
import { CRYPTO_PROFILE_V1, MESSAGE_AEAD_INFO_V1 } from '../profile';
import { xchachaOpen, xchachaSeal } from '../primitives';
import type { RatchetHeader } from './types';

const UINT32_MAX = 0xffff_ffff;

export function encodeRatchetHeader(header: RatchetHeader): Uint8Array {
  validateRatchetHeader(header);
  const out = new Uint8Array(40);
  out.set(header.dh, 0);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(32, header.pn, false);
  view.setUint32(36, header.n, false);
  return out;
}

export function decodeRatchetHeader(value: Uint8Array): RatchetHeader {
  if (value.length !== 40) throw new Error('Ratchet header must be 40 bytes');
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  const header: RatchetHeader = {
    dh: value.slice(0, 32),
    pn: view.getUint32(32, false),
    n: view.getUint32(36, false),
  };
  validateRatchetHeader(header);
  return header;
}

export function ratchetAssociatedData(externalAd: Uint8Array, header: RatchetHeader): Uint8Array {
  if (externalAd.length > UINT32_MAX) throw new Error('Associated data is too large');
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, externalAd.length, false);
  return concatBytes(MESSAGE_AEAD_INFO_V1, length, externalAd, encodeRatchetHeader(header));
}

export function sealRatchetPayload(
  messageKey: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  const sealed = xchachaSeal(messageKey, plaintext, associatedData, nonce);
  return concatBytes(sealed.nonce, sealed.ciphertext);
}

export function openRatchetPayload(messageKey: Uint8Array, payload: Uint8Array, associatedData: Uint8Array): Uint8Array {
  const minimum = CRYPTO_PROFILE_V1.nonceLength + CRYPTO_PROFILE_V1.tagLength;
  if (payload.length < minimum) throw new Error('Ratchet ciphertext is truncated');
  return xchachaOpen(
    messageKey,
    {
      nonce: payload.slice(0, CRYPTO_PROFILE_V1.nonceLength),
      ciphertext: payload.slice(CRYPTO_PROFILE_V1.nonceLength),
    },
    associatedData,
  );
}

export function validateRatchetHeader(header: RatchetHeader): void {
  if (header.dh.length !== CRYPTO_PROFILE_V1.x25519PublicKeyLength) throw new Error('Ratchet DH public key must be 32 bytes');
  if (!isUint32(header.pn) || !isUint32(header.n)) throw new Error('Ratchet counters must be uint32 values');
}

function isUint32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= UINT32_MAX;
}
