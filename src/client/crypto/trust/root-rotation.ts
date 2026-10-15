import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema, TrustedPeerDeviceRecord } from '../../storage/schema';
import { withCryptoLock } from '../../storage/locks';
import { deviceIdentityFingerprint } from '../../devices/api';
import { verifyDeviceCertificate } from '../../devices/certificate';
import { getChatDetailHttp } from '../../chat/api';
import { discoverPrekeyBundles } from '../prekeys/api';
import { planTrustedDeviceSet, type DeviceCertificateVerifier, type TrustedDeviceCandidate } from './device-trust';

export async function planExplicitRootRotation(
  existing: readonly TrustedPeerDeviceRecord[],
  userId: string,
  discovery: readonly TrustedDeviceCandidate[],
  rootDeviceId: string,
  expectedIdentityKey: string,
  confirmedFingerprint: string,
  verifier: DeviceCertificateVerifier = verifyDeviceCertificate,
): Promise<TrustedPeerDeviceRecord[]> {
  const root = discovery.find(device => device.device_id === rootDeviceId);
  if (!root || root.user_id !== userId || root.identity_public_key !== expectedIdentityKey || root.device_certificate || root.revoked_at) {
    throw new Error('La nueva raíz cambió o no es una identidad independiente activa.');
  }
  if (confirmedFingerprint.replace(/\s/g, '') !== deviceIdentityFingerprint(expectedIdentityKey).replace(/\s/g, '')) {
    throw new Error('La huella no coincide con la identidad confirmada por el otro canal.');
  }
  if (existing.length === 0 || existing.some(device => device.user_id !== userId || device.trust_mode === 'SELF')
    || existing.some(device => discovery.some(candidate => candidate.device_id === device.device_id))) {
    throw new Error('Primero deben retirarse los dispositivos de la identidad anterior; no se pueden reutilizar sus identificadores.');
  }
  const now = new Date().toISOString();
  const retired = existing.map(device => ({ ...device, revoked_at: device.revoked_at ?? now }));
  const replacement: TrustedPeerDeviceRecord = { user_id: userId, device_id: root.device_id,
    identity_public_key: root.identity_public_key, trust_mode: 'ROTATED', root_device_id: root.device_id,
    root_fingerprint: deviceIdentityFingerprint(root.identity_public_key), first_seen_at: now,
    verified_at: now, manual_verified_at: now };
  const added = await planTrustedDeviceSet([...retired, replacement], userId, discovery, verifier);
  return [...retired, replacement, ...added];
}

export async function rotateConversationRoot(
  db: IDBPDatabase<LocalDbSchema>, chatId: string, currentUserId: string, peerUserId: string,
  rootDeviceId: string, expectedIdentityKey: string, confirmedFingerprint: string,
): Promise<void> {
  if (currentUserId === peerUserId) throw new Error('Este flujo sólo reemplaza la identidad de otro participante.');
  const chat = await getChatDetailHttp(chatId);
  if (chat.chat_id !== chatId || !chat.participants.some(peer => peer.user_id === peerUserId)) {
    throw new Error('La identidad ya no pertenece a esta conversación.');
  }
  const discovery = await discoverPrekeyBundles(peerUserId, chatId);
  if (discovery.user_id !== peerUserId) throw new Error('El directorio devolvió otra identidad.');
  await withCryptoLock(db, `crypto:trust:${peerUserId}`, async () => {
    const before = await db.getAllFromIndex('trusted_peer_devices', 'by-user', peerUserId);
    const planned = await planExplicitRootRotation(before, peerUserId, discovery.devices, rootDeviceId,
      expectedIdentityKey, confirmedFingerprint);
    const tx = db.transaction(['trusted_peer_devices', 'sessions', 'skipped_message_keys', 'pending_outbox', 'settings'], 'readwrite');
    try {
      const trust = tx.objectStore('trusted_peer_devices');
      const current = await trust.index('by-user').getAll(peerUserId);
      const byId = new Map(current.map(device => [device.device_id, device]));
      if (before.length !== current.length || before.some(device => JSON.stringify(byId.get(device.device_id)) !== JSON.stringify(device))) {
        throw new Error('La confianza cambió en otra pestaña; volvé a cargar las huellas.');
      }
      const pending = await tx.objectStore('pending_outbox').getAll();
      if (pending.some(message => message.status !== 'COMMITTED')) {
        throw new Error('Resolvé los envíos pendientes antes de reemplazar una identidad. No se modificará ningún envío ambiguo.');
      }
      for (const device of planned) {
        const prior = await trust.get(device.device_id);
        if (prior && prior.user_id !== peerUserId) throw new Error('El identificador del dispositivo pertenece a otra identidad.');
      }
      for (const device of planned) await trust.put(device);
      const sessions = tx.objectStore('sessions');
      const retiredDeviceIds = new Set(before.map(device => device.device_id));
      for (const session of await sessions.getAll()) {
        if (!retiredDeviceIds.has(session.remote_device_id)) continue;
        const skipped = tx.objectStore('skipped_message_keys');
        for (const key of await skipped.index('by-session').getAllKeys(session.session_id)) await skipped.delete(key);
        await sessions.delete(session.session_id);
      }
      const now = new Date().toISOString();
      await tx.objectStore('settings').put({ key: `crypto:root-rotation:v1:${peerUserId}:${rootDeviceId}`, kind: 'json', value: {
        user_id: peerUserId, chat_id: chatId, root_device_id: rootDeviceId,
        fingerprint: deviceIdentityFingerprint(expectedIdentityKey), confirmed_at: now,
        retired_device_ids: before.map(device => device.device_id),
      } });
      // Recovery pins remain intact: rotating devices never silently downgrades recovery continuity.
      await tx.done;
    } catch (error) {
      try { tx.abort(); } catch { /* Transaction may already have aborted. */ }
      await tx.done.catch(() => undefined);
      throw error;
    }
  });
}
