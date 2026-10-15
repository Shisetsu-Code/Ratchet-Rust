import type { IDBPDatabase } from 'idb';
import { LocalStorageError, normalizeStorageError } from './errors';
import { canClaimLease, claimLease, leaseMatches } from './lease-model';
import type { LeaseSetting, LocalDbSchema } from './schema';

const DEFAULT_LEASE_TTL_MS = 9_000;
const DEFAULT_ACQUIRE_TIMEOUT_MS = 15_000;

export type CryptoFence =
  | { kind: 'web-lock'; lock_name: string }
  | {
      kind: 'lease';
      lock_name: string;
      lease_key: string;
      owner_id: string;
      fencing_token: number;
      lost: () => boolean;
    };

export async function withCryptoLock<T>(
  db: IDBPDatabase<LocalDbSchema>,
  lockName: string,
  fn: (fence: CryptoFence) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (typeof navigator !== 'undefined' && navigator.locks) {
    const options: LockOptions = signal ? { mode: 'exclusive', signal } : { mode: 'exclusive' };
    return navigator.locks.request(lockName, options, async () => fn({ kind: 'web-lock', lock_name: lockName }));
  }
  return withIndexedDbLease(db, lockName, fn, signal);
}

export async function withCryptoLocks<T>(
  db: IDBPDatabase<LocalDbSchema>,
  lockNames: readonly string[],
  fn: (fences: readonly CryptoFence[]) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const ordered = normalizeCryptoLockNames(lockNames);
  const acquired: CryptoFence[] = [];
  const acquire = async (index: number): Promise<T> => {
    if (index >= ordered.length) return fn(acquired);
    const lockName = ordered[index]!;
    return withCryptoLock(db, lockName, async (fence) => {
      acquired.push(fence);
      try {
        return await acquire(index + 1);
      } finally {
        acquired.pop();
      }
    }, signal);
  };
  return acquire(0);
}

export function normalizeCryptoLockNames(lockNames: readonly string[]): string[] {
  const unique = new Set<string>();
  for (const lockName of lockNames) {
    if (!lockName.startsWith('crypto:') || lockName.length <= 'crypto:'.length) {
      throw new LocalStorageError('CORRUPT_STATE', `Invalid cryptographic lock name: ${lockName}`);
    }
    if (unique.has(lockName)) {
      throw new LocalStorageError('CORRUPT_STATE', `Duplicate cryptographic lock name: ${lockName}`);
    }
    unique.add(lockName);
  }
  return [...unique].sort((a, b) => a.localeCompare(b));
}

export function assertLeaseRecord(current: LeaseSetting | undefined, fence: Extract<CryptoFence, { kind: 'lease' }>, now = Date.now()): void {
  if (fence.lost() || !leaseMatches(current, fence.owner_id, fence.fencing_token, now)) {
    throw new LocalStorageError('LEASE_LOST', 'IndexedDB lease ownership changed before commit');
  }
}

async function withIndexedDbLease<T>(
  db: IDBPDatabase<LocalDbSchema>,
  lockName: string,
  fn: (fence: CryptoFence) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const ownerId = crypto.randomUUID();
  const leaseKey = `lease:${lockName}`;
  const acquired = await acquireLease(db, leaseKey, ownerId, signal);
  let lost = false;
  const fence: Extract<CryptoFence, { kind: 'lease' }> = {
    kind: 'lease',
    lock_name: lockName,
    lease_key: leaseKey,
    owner_id: ownerId,
    fencing_token: acquired.fencing_token,
    lost: () => lost,
  };

  const renewalTimer = globalThis.setInterval(() => {
    void renewLease(db, fence).catch(() => {
      lost = true;
    });
  }, Math.floor(DEFAULT_LEASE_TTL_MS / 3));

  try {
    return await fn(fence);
  } finally {
    globalThis.clearInterval(renewalTimer);
    await releaseLease(db, fence).catch(() => undefined);
  }
}

async function acquireLease(
  db: IDBPDatabase<LocalDbSchema>,
  leaseKey: string,
  ownerId: string,
  signal?: AbortSignal,
): Promise<LeaseSetting> {
  const deadline = Date.now() + DEFAULT_ACQUIRE_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (signal?.aborted) throw signal.reason ?? new DOMException('Aborted', 'AbortError');
    try {
      const tx = db.transaction('settings', 'readwrite');
      const store = tx.objectStore('settings');
      const stored = await store.get(leaseKey);
      if (stored && stored.kind !== 'lease') {
        tx.abort();
        throw new LocalStorageError('CORRUPT_STATE', `Lease key ${leaseKey} contains non-lease data`);
      }
      const current = stored as LeaseSetting | undefined;
      const now = Date.now();
      if (canClaimLease(current, ownerId, now)) {
        const next = claimLease(current, leaseKey, ownerId, now, DEFAULT_LEASE_TTL_MS);
        await store.put(next);
        await tx.done;
        return next;
      }
      tx.abort();
    } catch (error) {
      if (error instanceof LocalStorageError) throw error;
      if (!(error instanceof DOMException && error.name === 'AbortError')) throw normalizeStorageError(error);
    }
    await delay(25 + Math.floor(Math.random() * 75));
  }
  throw new LocalStorageError('LOCK_TIMEOUT', `Timed out acquiring ${leaseKey}`);
}

async function renewLease(db: IDBPDatabase<LocalDbSchema>, fence: Extract<CryptoFence, { kind: 'lease' }>): Promise<void> {
  const tx = db.transaction('settings', 'readwrite');
  const store = tx.objectStore('settings');
  const stored = await store.get(fence.lease_key);
  const current = stored?.kind === 'lease' ? stored : undefined;
  if (!current || !leaseMatches(current, fence.owner_id, fence.fencing_token, Date.now())) {
    tx.abort();
    throw new LocalStorageError('LEASE_LOST', 'Cannot renew a lease owned by another tab');
  }
  const renewed: LeaseSetting = {
    key: current.key,
    kind: 'lease',
    owner_id: current.owner_id,
    fencing_token: current.fencing_token,
    expires_at: Date.now() + DEFAULT_LEASE_TTL_MS,
  };
  await store.put(renewed);
  await tx.done;
}

async function releaseLease(db: IDBPDatabase<LocalDbSchema>, fence: Extract<CryptoFence, { kind: 'lease' }>): Promise<void> {
  const tx = db.transaction('settings', 'readwrite');
  const store = tx.objectStore('settings');
  const stored = await store.get(fence.lease_key);
  if (stored?.kind === 'lease' && stored.owner_id === fence.owner_id && stored.fencing_token === fence.fencing_token) {
    const released: LeaseSetting = {
      key: stored.key,
      kind: 'lease',
      owner_id: null,
      fencing_token: stored.fencing_token,
      expires_at: 0,
    };
    await store.put(released);
  }
  await tx.done;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => globalThis.setTimeout(resolve, ms));
}
