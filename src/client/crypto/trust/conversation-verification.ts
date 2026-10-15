import type { IDBPDatabase } from 'idb';
import { getChatDetailHttp } from '../../chat/api';
import { deviceIdentityFingerprint } from '../../devices/api';
import type { LocalDbSchema, TrustedPeerDeviceRecord } from '../../storage/schema';
import { LocalStorageError } from '../../storage/errors';
import { discoverPrekeyBundles } from '../prekeys/api';
import {
  markTrustedRootManuallyVerified,
  verifyAndPersistTrustedDeviceSet,
} from './device-trust';

export type ConversationVerificationDevice = {
  device_id: string;
  identity_public_key: string;
  fingerprint: string;
  trust_mode: TrustedPeerDeviceRecord['trust_mode'] | 'UNVERIFIED';
  signer_device_id: string | null;
  manual_verified_at: string | null;
};

export type ConversationVerificationPeer = {
  user_id: string;
  participant_role: 'ADMIN' | 'CUSTOMER';
  devices: ConversationVerificationDevice[];
  root_verified: boolean;
  replacement_device_id?: string;
  identity_changed?: boolean;
};

export async function loadConversationVerification(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  currentUserId: string,
): Promise<ConversationVerificationPeer[]> {
  const chat = await getChatDetailHttp(chatId);
  const peers: ConversationVerificationPeer[] = [];

  for (const participant of chat.participants) {
    if (participant.user_id === currentUserId) continue;
    const discovery = await discoverPrekeyBundles(participant.user_id, chatId);
    if (discovery.user_id !== participant.user_id) throw new Error('Peer bundle discovery returned another user');

    try {
      await verifyAndPersistTrustedDeviceSet(db, participant.user_id, discovery.devices);
    } catch (error) {
      if (!(error instanceof LocalStorageError)) throw error;
      const prior = await db.getAllFromIndex('trusted_peer_devices', 'by-user', participant.user_id);
      if (prior.length === 0 && !(error.type === 'CORRUPT_STATE' && error.message === 'New independent identity root requires explicit approval')) throw error;
      const roots = discovery.devices.filter(device => !device.device_certificate);
      const replacement = prior.length > 0 && roots.length === 1 && !prior.some(device => discovery.devices.some(candidate => candidate.device_id === device.device_id))
        ? roots[0] : undefined;
      peers.push({ user_id: participant.user_id, participant_role: participant.participant_role,
        root_verified: false, identity_changed: true,
        ...(replacement ? { replacement_device_id: replacement.device_id } : {}),
        devices: discovery.devices.map(device => ({ device_id: device.device_id, identity_public_key: device.identity_public_key,
          fingerprint: deviceIdentityFingerprint(device.identity_public_key), trust_mode: 'UNVERIFIED',
          signer_device_id: null, manual_verified_at: null })) });
      continue;
    }
    const trusted = await db.getAllFromIndex('trusted_peer_devices', 'by-user', participant.user_id);
    const byDevice = new Map(trusted.map((record) => [record.device_id, record]));
    const devices = discovery.devices.map((bundle) => {
      const record = byDevice.get(bundle.device_id);
      if (!record || record.identity_public_key !== bundle.identity_public_key) {
        throw new Error('Peer device trust record is missing or changed');
      }
      return {
        device_id: record.device_id,
        identity_public_key: record.identity_public_key,
        fingerprint: deviceIdentityFingerprint(record.identity_public_key),
        trust_mode: record.trust_mode,
        signer_device_id: record.signer_device_id ?? null,
        manual_verified_at: record.manual_verified_at ?? null,
      } satisfies ConversationVerificationDevice;
    }).sort((left, right) => {
      const leftRoot = left.trust_mode === 'TOFU' || left.trust_mode === 'VERIFIED' || left.trust_mode === 'ROTATED';
      const rightRoot = right.trust_mode === 'TOFU' || right.trust_mode === 'VERIFIED' || right.trust_mode === 'ROTATED';
      if (leftRoot !== rightRoot) return leftRoot ? -1 : 1;
      return left.device_id.localeCompare(right.device_id);
    });

    const roots = devices.filter((device) => device.trust_mode === 'TOFU' || device.trust_mode === 'VERIFIED' || device.trust_mode === 'ROTATED');
    peers.push({
      user_id: participant.user_id,
      participant_role: participant.participant_role,
      devices,
      root_verified: roots.length === 1 && Boolean(roots[0]?.manual_verified_at),
    });
  }

  return peers.sort((left, right) => left.user_id.localeCompare(right.user_id));
}

export async function manuallyVerifyConversationRoot(
  db: IDBPDatabase<LocalDbSchema>,
  peerUserId: string,
  rootDeviceId: string,
  expectedIdentityPublicKey: string,
  confirmedFingerprint: string,
): Promise<void> {
  if (confirmedFingerprint.replace(/\s/g, '') !== deviceIdentityFingerprint(expectedIdentityPublicKey).replace(/\s/g, '')) {
    throw new Error('La huella no coincide con la identidad confirmada por el otro canal.');
  }
  await markTrustedRootManuallyVerified(db, peerUserId, rootDeviceId, expectedIdentityPublicKey);
}
