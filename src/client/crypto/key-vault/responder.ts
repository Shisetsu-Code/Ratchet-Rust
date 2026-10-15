import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema, PrekeyPurpose, PrekeyRecord } from '../../storage/schema';
import { LocalStorageError } from '../../storage/errors';
import type { PqXdhInitiationHeader, PqXdhResponderPrivateBundle, X25519KeyPair } from '../pqxdh/types';
import { wipe, x25519PublicKey } from '../primitives';
import { bytesToBase64Url } from '../local-state/base64url';
import { unwrapLocalSecret } from '../local-state/wrapping';
import { disposeDeviceIdentity, loadDeviceIdentity } from './identity';
import { prekeyPrivateAad } from './aad';

export type LoadedResponderBundle = {
  bundle: PqXdhResponderPrivateBundle;
  dispose: () => void;
};

export async function loadResponderBundleForHeader(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  header: PqXdhInitiationHeader,
): Promise<LoadedResponderBundle> {
  const identity = await loadDeviceIdentity(db, deviceId);
  const ownedSecrets: Uint8Array[] = [];
  const ownedPublics: Uint8Array[] = [];
  let disposed = false;

  try {
    const signedRecord = await requirePrekey(db, deviceId, header.signedPrekeyId, 'EC', 'SIGNED');
    const signedPrivate = await unwrapPrekeyPrivate(identity.masterKey, signedRecord);
    ownedSecrets.push(signedPrivate);
    const signedPublic = verifyEcPrivateMatchesRecord(signedPrivate, signedRecord);
    ownedPublics.push(signedPublic);

    const pqPurpose: PrekeyPurpose = header.pqPrekeyKind === 'ONE_TIME' ? 'ONE_TIME' : 'LAST_RESORT';
    const pqRecord = await requirePrekey(db, deviceId, header.pqPrekeyId, 'PQ', pqPurpose);
    const pqSecret = await unwrapPrekeyPrivate(identity.masterKey, pqRecord);
    ownedSecrets.push(pqSecret);

    let ecOneTimePrekey: (X25519KeyPair & { prekeyId: string }) | null = null;
    if (header.ecOneTimePrekeyId) {
      const ecRecord = await requirePrekey(db, deviceId, header.ecOneTimePrekeyId, 'EC', 'ONE_TIME');
      const ecPrivate = await unwrapPrekeyPrivate(identity.masterKey, ecRecord);
      ownedSecrets.push(ecPrivate);
      const ecPublic = verifyEcPrivateMatchesRecord(ecPrivate, ecRecord);
      ownedPublics.push(ecPublic);
      ecOneTimePrekey = {
        prekeyId: ecRecord.prekey_id,
        privateKey: ecPrivate,
        publicKey: ecPublic,
      };
    }

    const bundle: PqXdhResponderPrivateBundle = {
      identityKeyPair: identity.keyPair,
      signedPrekey: {
        prekeyId: signedRecord.prekey_id,
        privateKey: signedPrivate,
        publicKey: signedPublic,
      },
      pqPrekey: {
        prekeyId: pqRecord.prekey_id,
        secretKey: pqSecret,
        kind: header.pqPrekeyKind,
      },
      ecOneTimePrekey,
    };

    return {
      bundle,
      dispose() {
        if (disposed) return;
        disposed = true;
        for (const secret of ownedSecrets) wipe(secret);
        for (const publicKey of ownedPublics) wipe(publicKey);
        disposeDeviceIdentity(identity);
      },
    };
  } catch (error) {
    for (const secret of ownedSecrets) wipe(secret);
    for (const publicKey of ownedPublics) wipe(publicKey);
    disposeDeviceIdentity(identity);
    throw error;
  }
}

export function validateResponderPrekeyRecord(
  record: PrekeyRecord,
  deviceId: string,
  kind: 'EC' | 'PQ',
  purpose: PrekeyPurpose,
): void {
  if (record.device_id !== deviceId) throw new LocalStorageError('CORRUPT_STATE', 'Prekey belongs to another local device');
  if (record.kind !== kind) throw new LocalStorageError('CORRUPT_STATE', `Prekey ${record.prekey_id} has unexpected primitive kind`);
  if (record.purpose !== purpose) throw new LocalStorageError('CORRUPT_STATE', `Prekey ${record.prekey_id} has unexpected lifecycle purpose`);
  if (record.consumed_at) throw new LocalStorageError('CORRUPT_STATE', `Prekey ${record.prekey_id} was already consumed locally`);
}

async function requirePrekey(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  prekeyId: string,
  kind: 'EC' | 'PQ',
  purpose: PrekeyPurpose,
): Promise<PrekeyRecord> {
  const record = await db.get('prekeys', prekeyId);
  if (!record) throw new LocalStorageError('CORRUPT_STATE', `Referenced private prekey ${prekeyId} is unavailable`);
  validateResponderPrekeyRecord(record, deviceId, kind, purpose);
  return record;
}

async function unwrapPrekeyPrivate(masterKey: CryptoKey, record: PrekeyRecord): Promise<Uint8Array> {
  return unwrapLocalSecret(
    masterKey,
    { nonce: record.private_material_nonce, ciphertext: record.encrypted_private_material },
    prekeyPrivateAad(record.device_id, record.prekey_id, record.kind, record.purpose, record.public_key),
  );
}

function verifyEcPrivateMatchesRecord(privateKey: Uint8Array, record: PrekeyRecord): Uint8Array {
  const publicKey = x25519PublicKey(privateKey);
  if (bytesToBase64Url(publicKey) !== record.public_key) {
    wipe(publicKey);
    throw new LocalStorageError('CORRUPT_STATE', `EC private prekey ${record.prekey_id} does not match its stored public key`);
  }
  return publicKey;
}
