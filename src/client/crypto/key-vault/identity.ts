import type { IDBPDatabase } from 'idb';
import type { DeviceIdentityRecord, LocalDbSchema } from '../../storage/schema';
import { LocalStorageError } from '../../storage/errors';
import type { X25519KeyPair } from '../pqxdh/types';
import { randomBytes, wipe, x25519PublicKey } from '../primitives';
import { base64UrlToBytes, bytesToBase64Url } from '../local-state/base64url';
import { generateLocalMasterKey, unwrapLocalSecret, wrapLocalSecret } from '../local-state/wrapping';
import { deviceIdentityPrivateAad } from './aad';

export type GeneratedDeviceIdentity = {
  keyPair: X25519KeyPair;
  masterKey: CryptoKey;
};

export type LoadedDeviceIdentity = GeneratedDeviceIdentity & {
  deviceId: string;
  publicKeyEncoded: string;
};

export function generateDeviceIdentity(): Promise<GeneratedDeviceIdentity> {
  const privateKey = randomBytes(32);
  const publicKey = x25519PublicKey(privateKey);
  return generateLocalMasterKey().then((masterKey) => ({
    keyPair: { privateKey, publicKey },
    masterKey,
  }));
}

export async function persistGeneratedDeviceIdentity(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  generated: GeneratedDeviceIdentity,
): Promise<DeviceIdentityRecord> {
  const publicKeyEncoded = bytesToBase64Url(generated.keyPair.publicKey);
  const wrapped = await wrapLocalSecret(
    generated.masterKey,
    generated.keyPair.privateKey,
    deviceIdentityPrivateAad(deviceId, publicKeyEncoded),
  );
  const record: DeviceIdentityRecord = {
    local_device_id: deviceId,
    identity_public_key: publicKeyEncoded,
    encrypted_private_material: wrapped.ciphertext,
    private_material_nonce: wrapped.nonce,
    local_master_key: generated.masterKey,
    created_at: new Date().toISOString(),
  };
  const tx = db.transaction('device_identity', 'readwrite');
  const store = tx.objectStore('device_identity');
  const existing = await store.get(deviceId);
  if (existing) {
    tx.abort();
    if (existing.identity_public_key !== publicKeyEncoded) {
      throw new LocalStorageError('CORRUPT_STATE', 'Device identity already exists with different public key');
    }
    return existing;
  }
  await store.put(record);
  await tx.done;
  return record;
}

export async function loadDeviceIdentity(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
): Promise<LoadedDeviceIdentity> {
  const record = await db.get('device_identity', deviceId);
  if (!record || !record.local_master_key) throw new LocalStorageError('CORRUPT_STATE', 'Local device identity is unavailable');
  const publicKey = base64UrlToBytes(record.identity_public_key);
  const privateKey = await unwrapLocalSecret(
    record.local_master_key,
    { nonce: record.private_material_nonce, ciphertext: record.encrypted_private_material },
    deviceIdentityPrivateAad(deviceId, record.identity_public_key),
  );
  const derived = x25519PublicKey(privateKey);
  if (!equalBytes(derived, publicKey)) {
    wipe(privateKey, derived);
    throw new LocalStorageError('CORRUPT_STATE', 'Wrapped identity private key does not match its public key');
  }
  wipe(derived);
  return {
    deviceId,
    publicKeyEncoded: record.identity_public_key,
    keyPair: { privateKey, publicKey },
    masterKey: record.local_master_key,
  };
}

export function disposeDeviceIdentity(identity: LoadedDeviceIdentity | GeneratedDeviceIdentity): void {
  wipe(identity.keyPair.privateKey, identity.keyPair.publicKey);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let different = 0;
  for (let index = 0; index < a.length; index += 1) different |= a[index]! ^ b[index]!;
  return different === 0;
}
