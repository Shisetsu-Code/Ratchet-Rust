import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema } from '../../storage/schema';
import { countUnpublishedOneTimePrekeys, markPrekeyPublicationCommitted, prepareLocalPrekeyPublication } from '../key-vault/prekeys';
import { getOwnPrekeyStatus, publishPrekeysHttp } from './api';

export type PrekeyStockPolicy = {
  minimum: number;
  target: number;
};

export const DEFAULT_PREKEY_STOCK_POLICY: PrekeyStockPolicy = { minimum: 20, target: 40 };

export async function replenishPrekeys(
  db: IDBPDatabase<LocalDbSchema>,
  deviceId: string,
  policy: PrekeyStockPolicy = DEFAULT_PREKEY_STOCK_POLICY,
): Promise<void> {
  validatePolicy(policy);
  const status = await getOwnPrekeyStatus();
  if (status.device_id !== deviceId) throw new Error('Prekey status belongs to a different authenticated device');
  const unpublished = await countUnpublishedOneTimePrekeys(db, deviceId);
  const newEc = status.ec_available < policy.minimum
    ? Math.max(0, policy.target - status.ec_available - unpublished.ec)
    : 0;
  const newPq = status.pq_available < policy.minimum
    ? Math.max(0, policy.target - status.pq_available - unpublished.pq)
    : 0;

  if (status.bundle_present && unpublished.ec === 0 && unpublished.pq === 0 && newEc === 0 && newPq === 0) return;
  const prepared = await prepareLocalPrekeyPublication(db, deviceId, {
    createPrimaryIfMissing: !status.bundle_present,
    newEcOneTime: newEc,
    newPqOneTime: newPq,
  });
  await publishPrekeysHttp(prepared.request);
  await markPrekeyPublicationCommitted(db, deviceId, prepared.publishedRecordIds);
}

function validatePolicy(policy: PrekeyStockPolicy): void {
  if (!Number.isSafeInteger(policy.minimum) || !Number.isSafeInteger(policy.target)) throw new RangeError('Prekey stock policy must use integer counts');
  if (policy.minimum < 0 || policy.target < policy.minimum || policy.target > 100) {
    throw new RangeError('Prekey stock policy requires 0 <= minimum <= target <= 100');
  }
}
