import type { IDBPDatabase } from 'idb';
import { DEVICE_CERTIFICATE_PROTOCOL, DEVICE_CERTIFICATE_VERSION, decodeDeviceCertificate, type DeviceCertificatePayload } from '../../../shared/contracts/device-certificates';
import type { LocalDbSchema, TrustedPeerDeviceRecord } from '../../storage/schema';
import { LocalStorageError } from '../../storage/errors';
import { withCryptoLock } from '../../storage/locks';
import { verifyDeviceCertificate } from '../../devices/certificate';
import { base64UrlToBytes } from '../local-state/base64url';
import { deviceIdentityFingerprint } from '../../devices/api';

export type TrustedDeviceCandidate = {
  user_id: string;
  device_id: string;
  identity_public_key: string;
  device_certificate: string | null;
  account_authorized?: true | undefined;
  revoked_at?: string | null;
};

export type DeviceCertificateVerifier = (
  certificate: string,
  signerPublicIdentityKey: Uint8Array,
) => Promise<DeviceCertificatePayload>;

export async function ensureSelfDeviceTrust(
  db: IDBPDatabase<LocalDbSchema>,
  userId: string,
  deviceId: string,
  identityPublicKey: string,
): Promise<TrustedPeerDeviceRecord> {
  return withCryptoLock(db, trustLock(userId), async () => {
    const existing = await db.get('trusted_peer_devices', deviceId);
    if (existing) {
      assertTrustedIdentity(existing, userId, identityPublicKey);
      if (existing.trust_mode !== 'SELF') {
        throw new LocalStorageError('CORRUPT_STATE', 'Current local device is not anchored as SELF trust');
      }
      return existing;
    }
    const now = new Date().toISOString();
    const record: TrustedPeerDeviceRecord = {
      device_id: deviceId,
      user_id: userId,
      identity_public_key: identityPublicKey,
      trust_mode: 'SELF',
      root_device_id: deviceId,
      root_fingerprint: deviceIdentityFingerprint(identityPublicKey),
      first_seen_at: now,
      verified_at: now,
      manual_verified_at: now,
    };
    await db.add('trusted_peer_devices', record);
    return record;
  });
}

export async function verifyAndPersistTrustedDeviceSet(
  db: IDBPDatabase<LocalDbSchema>,
  userId: string,
  bundles: readonly TrustedDeviceCandidate[],
  verifier: DeviceCertificateVerifier = verifyDeviceCertificate,
): Promise<TrustedPeerDeviceRecord[]> {
  return withCryptoLock(db, trustLock(userId), async () => {
    const snapshot = await db.getAllFromIndex('trusted_peer_devices', 'by-user', userId);
    const planned = await planTrustedDeviceSet(snapshot, userId, bundles, verifier);
    if (planned.length === 0) return snapshot;

    const tx = db.transaction('trusted_peer_devices', 'readwrite');
    const store = tx.objectStore('trusted_peer_devices');
    const current = await store.index('by-user').getAll(userId);
    assertSnapshotUnchanged(snapshot, current);
    for (const record of planned) {
      const byId = await store.get(record.device_id);
      if (byId) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Device trust changed before commit');
      }
      await store.add(record);
    }
    await tx.done;
    return snapshot.concat(planned);
  });
}

export async function markTrustedRootManuallyVerified(
  db: IDBPDatabase<LocalDbSchema>,
  userId: string,
  deviceId: string,
  expectedIdentityPublicKey: string,
): Promise<TrustedPeerDeviceRecord> {
  return withCryptoLock(db, trustLock(userId), async () => {
    const record = await db.get('trusted_peer_devices', deviceId);
    if (!record) throw new LocalStorageError('CORRUPT_STATE', 'Trusted root is unavailable');
    assertTrustedIdentity(record, userId, expectedIdentityPublicKey);
    if (record.trust_mode !== 'TOFU' && record.trust_mode !== 'VERIFIED') {
      throw new LocalStorageError('CORRUPT_STATE', 'Only a TOFU root can be promoted by out-of-band verification');
    }
    if (record.manual_verified_at && record.trust_mode === 'VERIFIED') return record;

    const updated: TrustedPeerDeviceRecord = {
      ...record,
      trust_mode: 'VERIFIED',
      root_device_id: deviceId,
      root_fingerprint: deviceIdentityFingerprint(record.identity_public_key),
      manual_verified_at: record.manual_verified_at ?? new Date().toISOString(),
    };
    await db.put('trusted_peer_devices', updated);
    return updated;
  });
}

export async function planTrustedDeviceSet(
  existing: readonly TrustedPeerDeviceRecord[],
  userId: string,
  bundles: readonly TrustedDeviceCandidate[],
  verifier: DeviceCertificateVerifier,
): Promise<TrustedPeerDeviceRecord[]> {
  const trusted = new Map<string, TrustedPeerDeviceRecord>();
  for (const record of existing) {
    if (record.user_id !== userId) throw new LocalStorageError('CORRUPT_STATE', 'Trust snapshot contains another user');
    if (trusted.has(record.device_id)) throw new LocalStorageError('CORRUPT_STATE', 'Duplicate device in trust snapshot');
    trusted.set(record.device_id, record);
  }

  const byDevice = new Map<string, TrustedDeviceCandidate>();
  for (const bundle of bundles) {
    if (bundle.user_id !== userId) throw new LocalStorageError('CORRUPT_STATE', 'Discovered bundle belongs to another user');
    if (bundle.revoked_at) throw new LocalStorageError('CORRUPT_STATE', 'Discovered device is revoked');
    decodeIdentityKey(bundle.identity_public_key);
    if (byDevice.has(bundle.device_id)) throw new LocalStorageError('CORRUPT_STATE', 'Duplicate device in discovered bundle set');
    byDevice.set(bundle.device_id, bundle);
    const pinned = trusted.get(bundle.device_id);
    if (pinned) assertTrustedIdentity(pinned, userId, bundle.identity_public_key);
  }

  // The authenticated directory only emits this marker for active, authorized
  // account devices. Enrollment trusts that authority, while existing identity
  // pins and local revocations above remain mandatory. Legacy/offline callers
  // without the marker retain certificate-based trust.
  if (bundles.length > 0 && bundles.every(bundle => bundle.account_authorized === true)) {
    const now = new Date().toISOString();
    return bundles.filter(bundle => !trusted.has(bundle.device_id)).map(bundle => ({
      device_id: bundle.device_id,
      user_id: userId,
      identity_public_key: bundle.identity_public_key,
      trust_mode: 'ACCOUNT_AUTHORIZED',
      root_device_id: bundle.device_id,
      root_fingerprint: deviceIdentityFingerprint(bundle.identity_public_key),
      first_seen_at: now,
      verified_at: now,
    }));
  }

  for (const deviceId of byDevice.keys()) {
    const pinned = trusted.get(deviceId);
    if (!pinned) continue;
    trustedRoot(pinned, trusted);
    let ancestor = pinned;
    const visited = new Set<string>();
    while (ancestor.signer_device_id) {
      if (visited.has(ancestor.device_id) || !byDevice.has(ancestor.signer_device_id)) {
        throw new LocalStorageError('CORRUPT_STATE', 'Trusted signer is revoked or absent from active device discovery');
      }
      visited.add(ancestor.device_id);
      ancestor = trusted.get(ancestor.signer_device_id)!;
    }
  }

  const pending = new Map<string, TrustedDeviceCandidate>();
  for (const [deviceId, bundle] of byDevice) {
    if (!trusted.has(deviceId)) pending.set(deviceId, bundle);
  }
  if (existing.filter(record => !record.revoked_at && record.trust_mode !== 'CERTIFIED' && !record.signer_device_id).length > 1) {
    throw new LocalStorageError('CORRUPT_STATE', 'Multiple legacy identity roots require explicit approval');
  }
  if (pending.size === 0) return [];

  const planned: TrustedPeerDeviceRecord[] = [];
  const roots = [...pending.values()].filter(bundle => !bundle.device_certificate);
  if (roots.length > 0 && (existing.length > 0 || roots.length !== 1)) {
    throw new LocalStorageError('CORRUPT_STATE', 'New independent identity root requires explicit approval');
  }
  for (const root of pending.values()) {
    if (root.device_certificate) continue;
    const now = new Date().toISOString();
    const rootTrust: TrustedPeerDeviceRecord = {
      device_id: root.device_id,
      user_id: userId,
      identity_public_key: root.identity_public_key,
      trust_mode: 'TOFU',
      root_device_id: root.device_id,
      root_fingerprint: deviceIdentityFingerprint(root.identity_public_key),
      first_seen_at: now,
      verified_at: now,
    };
    trusted.set(root.device_id, rootTrust);
    pending.delete(root.device_id);
    planned.push(rootTrust);
  }

  while (pending.size > 0) {
    let progressed = false;
    for (const [deviceId, bundle] of pending) {
      if (!bundle.device_certificate) continue;
      const decoded = decodeCertificate(bundle.device_certificate);
      const signer = trusted.get(decoded.payload.signer_device_id);
      if (!signer) continue;
      if (signer.revoked_at || !byDevice.has(signer.device_id)) {
        throw new LocalStorageError('CORRUPT_STATE', 'Certificate signer is revoked or absent from active device discovery');
      }
      if (decoded.payload.signer_device_id === deviceId) {
        throw new LocalStorageError('CORRUPT_STATE', 'Device certificate cannot self-certify');
      }
      const signerKey = decodeIdentityKey(signer.identity_public_key);
      const payload = await verifier(bundle.device_certificate, signerKey);
      assertCertificatePayload(payload, bundle, userId, signer.device_id);
      const root = trustedRoot(signer, trusted);
      const now = new Date().toISOString();
      const record: TrustedPeerDeviceRecord = {
        device_id: bundle.device_id,
        user_id: userId,
        identity_public_key: bundle.identity_public_key,
        trust_mode: 'CERTIFIED',
        root_device_id: root.device_id,
        root_fingerprint: deviceIdentityFingerprint(root.identity_public_key),
        signer_device_id: signer.device_id,
        certificate: bundle.device_certificate,
        first_seen_at: now,
        verified_at: now,
      };
      trusted.set(deviceId, record);
      pending.delete(deviceId);
      planned.push(record);
      progressed = true;
    }
    if (!progressed) {
      throw new LocalStorageError(
        'CORRUPT_STATE',
        'Device certificate graph cannot be chained to an existing trusted identity',
      );
    }
  }

  return planned;
}

function decodeCertificate(certificate: string): ReturnType<typeof decodeDeviceCertificate> {
  try {
    return decodeDeviceCertificate(certificate);
  } catch (error) {
    throw new LocalStorageError('CORRUPT_STATE', 'Device certificate encoding is invalid', error);
  }
}

function assertCertificatePayload(
  payload: DeviceCertificatePayload,
  bundle: TrustedDeviceCandidate,
  userId: string,
  expectedSignerDeviceId: string,
): void {
  if (
    payload.protocol !== DEVICE_CERTIFICATE_PROTOCOL
    || payload.version !== DEVICE_CERTIFICATE_VERSION
    || payload.user_id !== userId
    || payload.device_id !== bundle.device_id
    || payload.signer_device_id !== expectedSignerDeviceId
    || payload.crypto_identity_public_key !== bundle.identity_public_key
  ) {
    throw new LocalStorageError('CORRUPT_STATE', 'Device certificate payload does not match the discovered device');
  }
}

function assertTrustedIdentity(record: TrustedPeerDeviceRecord, userId: string, identityPublicKey: string): void {
  if (record.revoked_at) throw new LocalStorageError('CORRUPT_STATE', 'Trusted device is revoked');
  if (record.user_id !== userId || record.identity_public_key !== identityPublicKey) {
    throw new LocalStorageError('CORRUPT_STATE', 'Trusted device identity changed');
  }
}

function trustedRoot(record: TrustedPeerDeviceRecord, trusted: ReadonlyMap<string, TrustedPeerDeviceRecord>): TrustedPeerDeviceRecord {
  const seen = new Set<string>();
  let root = record;
  while (root.trust_mode === 'CERTIFIED' || root.signer_device_id) {
    if (seen.has(root.device_id)) throw new LocalStorageError('CORRUPT_STATE', 'Trusted certificate graph contains a cycle');
    seen.add(root.device_id);
    const signer = root.signer_device_id ? trusted.get(root.signer_device_id) : undefined;
    if (!signer || signer.revoked_at) throw new LocalStorageError('CORRUPT_STATE', 'Trusted certificate root is unavailable');
    root = signer;
  }
  if (root.revoked_at) throw new LocalStorageError('CORRUPT_STATE', 'Trusted certificate root is revoked');
  return root;
}

function decodeIdentityKey(encoded: string): Uint8Array {
  const key = base64UrlToBytes(encoded);
  if (key.length !== 32) throw new LocalStorageError('CORRUPT_STATE', 'Trusted X25519 identity key must be 32 bytes');
  return key;
}

function assertSnapshotUnchanged(
  before: readonly TrustedPeerDeviceRecord[],
  after: readonly TrustedPeerDeviceRecord[],
): void {
  if (before.length !== after.length) throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Device trust changed before commit');
  const current = new Map(after.map((record) => [record.device_id, record]));
  for (const record of before) {
    const match = current.get(record.device_id);
    if (!match || JSON.stringify(match) !== JSON.stringify(record)) {
      throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Device trust changed before commit');
    }
  }
}

function trustLock(userId: string): string {
  return `crypto:trust:${userId}`;
}
