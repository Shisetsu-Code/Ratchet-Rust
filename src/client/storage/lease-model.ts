import type { LeaseSetting } from './schema';

export function canClaimLease(current: LeaseSetting | undefined, ownerId: string, now: number): boolean {
  return current === undefined || current.owner_id === null || current.owner_id === ownerId || current.expires_at <= now;
}

export function claimLease(current: LeaseSetting | undefined, key: string, ownerId: string, now: number, ttlMs: number): LeaseSetting {
  const fencingToken = (current?.fencing_token ?? 0) + 1;
  return {
    key,
    kind: 'lease',
    owner_id: ownerId,
    fencing_token: fencingToken,
    expires_at: now + ttlMs,
  };
}

export function leaseMatches(current: LeaseSetting | undefined, ownerId: string, fencingToken: number, now: number): boolean {
  return current?.owner_id === ownerId && current.fencing_token === fencingToken && current.expires_at > now;
}
