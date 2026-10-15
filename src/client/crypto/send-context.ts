import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema } from '../storage/schema';
import { LocalStorageError } from '../storage/errors';
import { base64UrlToBytes } from './local-state/base64url';
import { wipe } from './primitives';

export type SendKeyContext = {
  deviceId: string;
  publicKeyEncoded: string;
  masterKey: CryptoKey;
};

/**
 * Loads only the long-lived, non-extractable key material needed by the
 * established-session send hot path. The raw X25519 identity private key is
 * intentionally not unwrapped here; it is loaded only when PQXDH bootstrap is
 * actually required for a new peer device.
 */
export async function loadSendKeyContext(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
): Promise<SendKeyContext> {
  const record = await db.get('device_identity', deviceId);
  if (!record || !record.local_master_key) {
    throw new LocalStorageError('CORRUPT_STATE', 'Local device identity is unavailable');
  }
  const publicKey = base64UrlToBytes(record.identity_public_key);
  try {
    if (publicKey.length !== 32) {
      throw new LocalStorageError('CORRUPT_STATE', 'Stored local X25519 identity key must be 32 bytes');
    }
  } finally {
    wipe(publicKey);
  }
  return {
    deviceId,
    publicKeyEncoded: record.identity_public_key,
    masterKey: record.local_master_key,
  };
}
