import type { IDBPDatabase } from 'idb';
import type { PublishPrekeysRequest } from '../../../shared/contracts/prekeys';
import { uuidv7 } from '../../../shared/ids/uuidv7';
import type { LocalDbSchema, PrekeyPurpose, PrekeyRecord } from '../../storage/schema';
import { LocalStorageError } from '../../storage/errors';
import { withCryptoLock } from '../../storage/locks';
import { encodeMlKem1024PublicKey, encodeX25519PublicKey } from '../encoding';
import { bytesToBase64Url } from '../local-state/base64url';
import { wrapLocalSecret } from '../local-state/wrapping';
import { mlKem1024Keygen, randomBytes, wipe, x25519PublicKey } from '../primitives';
import { xed25519Sign } from '../xeddsa';
import { disposeDeviceIdentity, loadDeviceIdentity } from './identity';
import { prekeyPrivateAad } from './aad';

export type PreparePublicationOptions = {
  createPrimaryIfMissing: boolean;
  newEcOneTime: number;
  newPqOneTime: number;
};

export type PreparedLocalPublication = {
  request: PublishPrekeysRequest;
  publishedRecordIds: string[];
};

export async function prepareLocalPrekeyPublication(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  options: PreparePublicationOptions,
): Promise<PreparedLocalPublication> {
  validateCount(options.newEcOneTime);
  validateCount(options.newPqOneTime);
  return withCryptoLock(db, `crypto:vault:${deviceId}`, async () => {
    const identity = await loadDeviceIdentity(db, deviceId);
    try {
      const existing = await db.getAllFromIndex('prekeys', 'by-device', deviceId);
      const signed = uniquePrimary(existing, 'EC', 'SIGNED');
      const lastResort = uniquePrimary(existing, 'PQ', 'LAST_RESORT');
      if ((!signed || !lastResort) && !options.createPrimaryIfMissing) {
        throw new LocalStorageError('CORRUPT_STATE', 'Server has a prekey bundle but local primary private material is missing');
      }

      const generated: PrekeyRecord[] = [];
      const signedRecord = signed ?? await generateEcRecord(
        identity.masterKey,
        identity.keyPair.privateKey,
        deviceId,
        'SIGNED',
        true,
      );
      if (!signed) generated.push(signedRecord);
      const lastResortRecord = lastResort ?? await generatePqRecord(
        identity.masterKey,
        identity.keyPair.privateKey,
        deviceId,
        'LAST_RESORT',
      );
      if (!lastResort) generated.push(lastResortRecord);

      for (let index = 0; index < options.newEcOneTime; index += 1) {
        generated.push(await generateEcRecord(identity.masterKey, identity.keyPair.privateKey, deviceId, 'ONE_TIME', false));
      }
      for (let index = 0; index < options.newPqOneTime; index += 1) {
        generated.push(await generatePqRecord(identity.masterKey, identity.keyPair.privateKey, deviceId, 'ONE_TIME'));
      }

      if (generated.length > 0) {
        const tx = db.transaction('prekeys', 'readwrite');
        for (const record of generated) await tx.store.add(record);
        await tx.done;
      }

      const all = [...existing, ...generated];
      const unpublishedEc = all.filter((record) => record.kind === 'EC' && record.purpose === 'ONE_TIME' && !record.published_at);
      const unpublishedPq = all.filter((record) => record.kind === 'PQ' && record.purpose === 'ONE_TIME' && !record.published_at);
      const request: PublishPrekeysRequest = {
        identity_public_key: identity.publicKeyEncoded,
        signed_prekey: signedPublic(signedRecord),
        pq_last_resort_prekey: pqSignedPublic(lastResortRecord),
        ec_one_time_prekeys: unpublishedEc.map((record) => ({ prekey_id: record.prekey_id, public_key: record.public_key })),
        pq_one_time_prekeys: unpublishedPq.map(pqSignedPublic),
      };
      return {
        request,
        publishedRecordIds: [
          signedRecord.prekey_id,
          lastResortRecord.prekey_id,
          ...unpublishedEc.map((record) => record.prekey_id),
          ...unpublishedPq.map((record) => record.prekey_id),
        ],
      };
    } finally {
      disposeDeviceIdentity(identity);
    }
  });
}

export async function markPrekeyPublicationCommitted(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  prekeyIds: readonly string[],
): Promise<void> {
  const now = new Date().toISOString();
  const tx = db.transaction('prekeys', 'readwrite');
  for (const prekeyId of prekeyIds) {
    const current = await tx.store.get(prekeyId);
    if (!current || current.device_id !== deviceId) {
      tx.abort();
      throw new LocalStorageError('CORRUPT_STATE', `Published prekey ${prekeyId} disappeared locally`);
    }
    if (!current.published_at) await tx.store.put({ ...current, published_at: now });
  }
  await tx.done;
}

export async function countUnpublishedOneTimePrekeys(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
): Promise<{ ec: number; pq: number }> {
  const records = await db.getAllFromIndex('prekeys', 'by-device', deviceId);
  return {
    ec: records.filter((record) => record.kind === 'EC' && record.purpose === 'ONE_TIME' && !record.published_at).length,
    pq: records.filter((record) => record.kind === 'PQ' && record.purpose === 'ONE_TIME' && !record.published_at).length,
  };
}

async function generateEcRecord(
  masterKey: CryptoKey,
  identityPrivateKey: Uint8Array,
  deviceId: string,
  purpose: Extract<PrekeyPurpose, 'SIGNED' | 'ONE_TIME'>,
  sign: boolean,
): Promise<PrekeyRecord> {
  const privateKey = randomBytes(32);
  const publicKeyBytes = x25519PublicKey(privateKey);
  const publicKey = bytesToBase64Url(publicKeyBytes);
  const prekeyId = uuidv7();
  let signatureBytes: Uint8Array | undefined;
  try {
    if (sign) signatureBytes = await xed25519Sign(identityPrivateKey, encodeX25519PublicKey(publicKeyBytes));
    const wrapped = await wrapLocalSecret(masterKey, privateKey, prekeyPrivateAad(deviceId, prekeyId, 'EC', purpose, publicKey));
    return {
      prekey_id: prekeyId,
      device_id: deviceId,
      kind: 'EC',
      purpose,
      public_key: publicKey,
      ...(signatureBytes ? { signature: bytesToBase64Url(signatureBytes) } : {}),
      encrypted_private_material: wrapped.ciphertext,
      private_material_nonce: wrapped.nonce,
      created_at: new Date().toISOString(),
    };
  } finally {
    wipe(privateKey, publicKeyBytes);
    if (signatureBytes) wipe(signatureBytes);
  }
}

async function generatePqRecord(
  masterKey: CryptoKey,
  identityPrivateKey: Uint8Array,
  deviceId: string,
  purpose: Extract<PrekeyPurpose, 'LAST_RESORT' | 'ONE_TIME'>,
): Promise<PrekeyRecord> {
  const pair = mlKem1024Keygen();
  const publicKey = bytesToBase64Url(pair.publicKey);
  const prekeyId = uuidv7();
  let signatureBytes: Uint8Array | undefined;
  try {
    signatureBytes = await xed25519Sign(identityPrivateKey, encodeMlKem1024PublicKey(pair.publicKey));
    const wrapped = await wrapLocalSecret(masterKey, pair.secretKey, prekeyPrivateAad(deviceId, prekeyId, 'PQ', purpose, publicKey));
    return {
      prekey_id: prekeyId,
      device_id: deviceId,
      kind: 'PQ',
      purpose,
      public_key: publicKey,
      signature: bytesToBase64Url(signatureBytes),
      encrypted_private_material: wrapped.ciphertext,
      private_material_nonce: wrapped.nonce,
      created_at: new Date().toISOString(),
    };
  } finally {
    wipe(pair.publicKey, pair.secretKey);
    if (signatureBytes) wipe(signatureBytes);
  }
}

function uniquePrimary(records: readonly PrekeyRecord[], kind: 'EC' | 'PQ', purpose: PrekeyPurpose): PrekeyRecord | undefined {
  const matching = records.filter((record) => record.kind === kind && record.purpose === purpose);
  if (matching.length > 1) throw new LocalStorageError('CORRUPT_STATE', `Multiple ${kind}/${purpose} prekeys exist locally`);
  return matching[0];
}

function signedPublic(record: PrekeyRecord): PublishPrekeysRequest['signed_prekey'] {
  if (record.kind !== 'EC' || record.purpose !== 'SIGNED' || !record.signature) {
    throw new LocalStorageError('CORRUPT_STATE', 'Signed EC prekey is malformed');
  }
  return { prekey_id: record.prekey_id, public_key: record.public_key, signature: record.signature };
}

function pqSignedPublic(record: PrekeyRecord): PublishPrekeysRequest['pq_last_resort_prekey'] {
  if (record.kind !== 'PQ' || !record.signature) throw new LocalStorageError('CORRUPT_STATE', 'Signed PQ prekey is malformed');
  return { prekey_id: record.prekey_id, public_key: record.public_key, signature: record.signature };
}

function validateCount(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 100) throw new RangeError('Prekey generation count must be between 0 and 100');
}
