import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema } from '../../storage/schema';
import { generateLocalMasterKey } from './wrapping';

export async function ensureLocalMasterKey(
  db: IDBPDatabase<LocalDbSchema>,
  localDeviceId: string,
): Promise<CryptoKey> {
  const generated = await generateLocalMasterKey();
  const tx = db.transaction('device_identity', 'readwrite');
  const store = tx.objectStore('device_identity');
  const identity = await store.get(localDeviceId);
  if (!identity) {
    tx.abort();
    throw new Error('Local cryptographic device identity is missing');
  }
  if (identity.local_master_key) {
    const existing = identity.local_master_key;
    await tx.done;
    return existing;
  }
  const next = { ...identity, local_master_key: generated };
  await store.put(next);
  await tx.done;
  return generated;
}
