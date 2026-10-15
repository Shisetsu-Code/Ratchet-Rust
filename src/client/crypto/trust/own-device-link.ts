import type { IDBPDatabase } from 'idb';
import type { CurrentSessionResponse } from '../../../shared/contracts/session';
import type { LocalDbSchema, TrustedPeerDeviceRecord } from '../../storage/schema';
import { withCryptoLock } from '../../storage/locks';
import { listOwnDevices, deviceIdentityFingerprint, type OwnDevice } from '../../devices/api';
import { verifyDeviceCertificate } from '../../devices/certificate';
import { base64UrlToBytes } from '../local-state/base64url';
import { loadDeviceIdentity, disposeDeviceIdentity } from '../key-vault/identity';
import { ensureSelfDeviceTrust } from './device-trust';

export async function linkOwnDeviceToVerifiedRoot(db: IDBPDatabase<LocalDbSchema>, session: CurrentSessionResponse, root: OwnDevice, fingerprint: string): Promise<void> {
  if (fingerprint.replace(/\s/g, '') !== deviceIdentityFingerprint(root.crypto_identity_public_key).replace(/\s/g, '')) throw new Error('La huella no coincide con el navegador de origen.');
  if (root.device_id === session.device_id || root.revoked_at) throw new Error('Elegí otro navegador activo como origen.');
  const devices = await listOwnDevices();
  const freshRoot = devices.find(d => d.device_id === root.device_id);
  const self = devices.find(d => d.device_id === session.device_id);
  if (!freshRoot || freshRoot.revoked_at || freshRoot.crypto_identity_public_key !== root.crypto_identity_public_key || !self?.device_certificate || self.revoked_at) throw new Error('Primero vinculá este navegador desde el navegador de origen.');
  const certificate = self.device_certificate;
  const identity = await loadDeviceIdentity(db, session.device_id);
  try {
    const proof = await verifyDeviceCertificate(certificate, base64UrlToBytes(root.crypto_identity_public_key));
    if (proof.user_id !== session.user_id || proof.device_id !== session.device_id || proof.signer_device_id !== root.device_id || proof.crypto_identity_public_key !== identity.publicKeyEncoded) throw new Error('El certificado no corresponde a este navegador.');
    await ensureSelfDeviceTrust(db, session.user_id, session.device_id, identity.publicKeyEncoded);
    await withCryptoLock(db, `crypto:trust:${session.user_id}`, async () => {
      const tx = db.transaction('trusted_peer_devices', 'readwrite');
      const records = await tx.store.index('by-user').getAll(session.user_id);
      const local = records.find(d => d.device_id === session.device_id);
      if (!local || local.trust_mode !== 'SELF' || records.some(d => d.device_id !== session.device_id && d.device_id !== root.device_id)) {
        tx.abort(); await tx.done.catch(() => undefined); throw new Error('Esta identidad ya tiene vínculos; no se puede reemplazar automáticamente.');
      }
      const pinnedRoot = records.find(d => d.device_id === root.device_id);
      if (pinnedRoot && (pinnedRoot.identity_public_key !== root.crypto_identity_public_key || pinnedRoot.revoked_at)) {
        tx.abort(); await tx.done.catch(() => undefined); throw new Error('La identidad de origen cambió.');
      }
      const now = new Date().toISOString();
      const rootRecord: TrustedPeerDeviceRecord = { device_id: root.device_id, user_id: session.user_id, identity_public_key: root.crypto_identity_public_key, trust_mode: 'VERIFIED', root_device_id: root.device_id, root_fingerprint: deviceIdentityFingerprint(root.crypto_identity_public_key), first_seen_at: pinnedRoot?.first_seen_at ?? now, verified_at: now, manual_verified_at: now };
      await tx.store.put(rootRecord);
      await tx.store.put({ ...local, signer_device_id: root.device_id, certificate, root_device_id: root.device_id, root_fingerprint: deviceIdentityFingerprint(root.crypto_identity_public_key) });
      await tx.done;
    });
  } finally { disposeDeviceIdentity(identity); }
}
