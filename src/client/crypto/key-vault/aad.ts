import { concatBytes, utf8 } from '../encoding';
import type { PrekeyPurpose } from '../../storage/schema';

const IDENTITY_DOMAIN = utf8('RatchetSecureSupport/device-identity/v1');
const PREKEY_DOMAIN = utf8('RatchetSecureSupport/prekey-private/v1');

export function deviceIdentityPrivateAad(deviceId: string, publicKey: string): Uint8Array {
  return fields(IDENTITY_DOMAIN, deviceId, publicKey);
}

export function prekeyPrivateAad(
  deviceId: string,
  prekeyId: string,
  kind: 'EC' | 'PQ',
  purpose: PrekeyPurpose,
  publicKey: string,
): Uint8Array {
  return fields(PREKEY_DOMAIN, deviceId, prekeyId, kind, purpose, publicKey);
}

function fields(domain: Uint8Array, ...values: readonly string[]): Uint8Array {
  return concatBytes(domain, ...values.map((value) => lengthPrefix(utf8(value))));
}

function lengthPrefix(value: Uint8Array): Uint8Array {
  const size = new Uint8Array(4);
  new DataView(size.buffer).setUint32(0, value.length, false);
  return concatBytes(size, value);
}
