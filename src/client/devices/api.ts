import type { IDBPDatabase } from 'idb';
import { z } from 'zod';
import type { CurrentSessionResponse } from '../../shared/contracts/session';
import { createDeviceCertificate } from './certificate';
import { disposeDeviceIdentity, loadDeviceIdentity } from '../crypto/key-vault/identity';
import { sha256Digest } from '../crypto/primitives';
import { base64UrlToBytes, bytesToBase64Url } from '../crypto/local-state/base64url';
import type { LocalDbSchema } from '../storage/schema';
import { apiFetch } from '../transport/api';

export const OwnDeviceSchema = z.object({
  device_id: z.string().uuid(),
  display_name: z.string(),
  crypto_identity_public_key: z.string().min(16),
  created_at: z.string(),
  authorized_at: z.string().nullable(),
  revoked_at: z.string().nullable(),
  last_seen_at: z.string().nullable(),
  crypto_ready: z.union([z.literal(0), z.literal(1)]).transform(Boolean),
  device_certificate: z.string().nullable().optional(),
  certified: z.union([z.literal(0), z.literal(1)]).transform(Boolean),
});

export type OwnDevice = z.infer<typeof OwnDeviceSchema>;

export async function listOwnDevices(): Promise<OwnDevice[]> {
  return apiFetch('/api/v1/devices', {}, (value) => z.object({ devices: z.array(OwnDeviceSchema) }).passthrough().parse(value).devices);
}

export async function certifyPendingDevice(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  target: OwnDevice,
): Promise<void> {
  if (!session.device_authorized) throw new Error('Current device must be authorized before certifying another device');
  if (target.device_id === session.device_id) throw new Error('A device cannot certify itself');
  if (target.revoked_at) throw new Error('Target device is revoked');
  if (!target.crypto_ready) throw new Error('Target device must publish its prekey bundle before certification');

  const identity = await loadDeviceIdentity(db, session.device_id);
  try {
    const certificate = await createDeviceCertificate(identity.keyPair.privateKey, {
      user_id: session.user_id,
      device_id: target.device_id,
      signer_device_id: session.device_id,
      crypto_identity_public_key: target.crypto_identity_public_key,
    });
    await apiFetch(`/api/v1/devices/${encodeURIComponent(target.device_id)}/certificate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ certificate }),
    }, () => undefined, { retryMode: 'idempotent' });
  } finally {
    disposeDeviceIdentity(identity);
  }
}

export async function approvePendingDevice(deviceId: string): Promise<void> {
  await apiFetch(`/api/v1/devices/${encodeURIComponent(deviceId)}/approve`, { method: 'POST' }, () => undefined, { retryMode: 'idempotent' });
}

export async function revokeDeviceHttp(deviceId: string): Promise<void> {
  await apiFetch(`/api/v1/devices/${encodeURIComponent(deviceId)}`, { method: 'DELETE' }, () => undefined, { retryMode: 'idempotent' });
}

export function deviceIdentityFingerprint(publicKey: string): string {
  const decoded = base64UrlToBytes(publicKey);
  const digest = bytesToBase64Url(sha256Digest(decoded));
  decoded.fill(0);
  return digest.match(/.{1,6}/g)?.join(' ') ?? digest;
}
