import type { IDBPDatabase } from 'idb';
import type { PublicPrekeyBundle, ConsumePrekeyResponse } from '../../../shared/contracts/prekeys';
import { uuidv7 } from '../../../shared/ids/uuidv7';
import { getChatDetailHttp } from '../../chat/api';
import type { JsonSetting, LocalDbSchema } from '../../storage/schema';
import { LocalStorageError } from '../../storage/errors';
import { assertRemoteIdentityPinned, assertEstablishedRatchetSession } from '../local-state/ratchet-store';
import { base64UrlToBytes } from '../local-state/base64url';
import { consumePrekeysHttp, discoverPrekeyBundles } from '../prekeys/api';
import { consumedPrekeysToPqXdhBundle } from '../prekeys/mapping';
import { ensureSelfDeviceTrust, verifyAndPersistTrustedDeviceSet } from '../trust/device-trust';
import type { AtomicMultiDeviceTarget } from './atomic-send';

export type TargetResolutionErrorType =
  | 'NO_CRYPTO_RECIPIENTS'
  | 'PAIRWISE_SESSION_PENDING'
  | 'SERVER_DEVICE_SET_INVALID'
  | 'CONSUMED_BUNDLE_MISMATCH';

export class TargetResolutionError extends Error {
  constructor(readonly type: TargetResolutionErrorType, message: string) {
    super(message);
  }
}

type CachedRecipientDevice = {
  user_id: string;
  device_id: string;
  identity_public_key: string;
};

type CachedRecipientSet = {
  version: 1;
  chat_id: string;
  sender_device_id: string;
  devices: CachedRecipientDevice[];
};

export async function resolveAtomicTargets(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  senderUserId: string,
  senderDeviceId: string,
  senderIdentityPublicKey: string,
): Promise<AtomicMultiDeviceTarget[]> {
  const chat = await getChatDetailHttp(chatId);
  if (!chat.participants.some((participant) => participant.user_id === senderUserId)) {
    throw new TargetResolutionError('SERVER_DEVICE_SET_INVALID', 'Authenticated sender is absent from chat participants');
  }

  await ensureSelfDeviceTrust(db, senderUserId, senderDeviceId, senderIdentityPublicKey);
  const participants = chat.participants.slice().sort((left, right) => left.user_id.localeCompare(right.user_id));
  const discoveries = await Promise.all(participants.map(async (participant) => ({
    participant,
    response: await discoverPrekeyBundles(participant.user_id, chatId),
  })));
  const discovered: PublicPrekeyBundle[] = [];
  for (const { participant, response } of discoveries) {
    if (response.user_id !== participant.user_id) {
      throw new TargetResolutionError('SERVER_DEVICE_SET_INVALID', 'Bundle discovery returned another user identity');
    }
    if (participant.user_id === senderUserId) {
      const self = response.devices.find((device) => device.device_id === senderDeviceId);
      if (!self || self.identity_public_key !== senderIdentityPublicKey) {
        throw new TargetResolutionError('SERVER_DEVICE_SET_INVALID', 'Current device is missing its matching public prekey bundle');
      }
    }
    await verifyAndPersistTrustedDeviceSet(db, participant.user_id, response.devices);
    discovered.push(...response.devices);
  }

  const byDevice = new Map<string, PublicPrekeyBundle>();
  for (const bundle of discovered) {
    if (byDevice.has(bundle.device_id)) {
      throw new TargetResolutionError('SERVER_DEVICE_SET_INVALID', 'Duplicate device_id appeared across chat participants');
    }
    byDevice.set(bundle.device_id, bundle);
  }
  byDevice.delete(senderDeviceId);
  if (byDevice.size === 0) {
    throw new TargetResolutionError('NO_CRYPTO_RECIPIENTS', 'Chat has no other crypto-ready device');
  }

  await persistRecipientSetCache(db, chatId, senderDeviceId, Array.from(byDevice.values()));

  const targets: AtomicMultiDeviceTarget[] = [];
  const ordered = Array.from(byDevice.values()).sort((left, right) => left.device_id.localeCompare(right.device_id));
  for (const bundle of ordered) {
    const lockName = pairLock(senderDeviceId, bundle.device_id);
    const session = await db.getFromIndex('sessions', 'by-lock-name', lockName);
    const discoveredIdentity = decodeIdentity(bundle.identity_public_key);
    if (session) {
      if (session.establishment_state !== 'ESTABLISHED') {
        throw new TargetResolutionError('PAIRWISE_SESSION_PENDING', `Pairwise session for ${bundle.device_id} is awaiting first-message acceptance`);
      }
      assertEstablishedRatchetSession(session);
      assertRemoteIdentityPinned(session, discoveredIdentity);
      targets.push({
        mode: 'established',
        session_id: session.session_id,
        recipient_user_id: bundle.user_id,
        recipient_device_id: bundle.device_id,
      });
      continue;
    }

    const consumed = await consumePrekeysHttp({
      chat_id: chatId,
      recipient_user_id: bundle.user_id,
      recipient_device_id: bundle.device_id,
    });
    assertConsumedBundleMatchesDiscovery(bundle, consumed);
    targets.push({
      mode: 'bootstrap',
      session_id: uuidv7(),
      recipient_user_id: bundle.user_id,
      recipient_device_id: bundle.device_id,
      bundle: consumedPrekeysToPqXdhBundle(consumed),
    });
  }
  return targets;
}

export async function resolveCachedAtomicTargets(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  senderDeviceId: string,
): Promise<AtomicMultiDeviceTarget[] | null> {
  const setting = await db.get('settings', recipientSetCacheKey(chatId, senderDeviceId));
  const cached = parseCachedRecipientSet(setting?.kind === 'json' ? setting.value : undefined);
  if (!cached || cached.chat_id !== chatId || cached.sender_device_id !== senderDeviceId || cached.devices.length === 0) return null;

  const targets: AtomicMultiDeviceTarget[] = [];
  for (const device of cached.devices) {
    const trusted = await db.get('trusted_peer_devices', device.device_id);
    if (!trusted) return null;
    if (trusted.user_id !== device.user_id || trusted.identity_public_key !== device.identity_public_key) {
      throw new LocalStorageError('CORRUPT_STATE', 'Cached recipient identity no longer matches the trusted device record');
    }
    const lockName = pairLock(senderDeviceId, device.device_id);
    const session = await db.getFromIndex('sessions', 'by-lock-name', lockName);
    if (!session || session.establishment_state !== 'ESTABLISHED') return null;
    assertEstablishedRatchetSession(session);
    assertRemoteIdentityPinned(session, decodeIdentity(device.identity_public_key));
    targets.push({
      mode: 'established',
      session_id: session.session_id,
      recipient_user_id: device.user_id,
      recipient_device_id: device.device_id,
    });
  }
  return targets.sort((left, right) => left.recipient_device_id.localeCompare(right.recipient_device_id));
}

export function assertConsumedBundleMatchesDiscovery(
  discovered: PublicPrekeyBundle,
  consumed: ConsumePrekeyResponse,
): void {
  if (
    consumed.bundle.device_id !== discovered.device_id
    || consumed.bundle.user_id !== discovered.user_id
    || consumed.bundle.identity_public_key !== discovered.identity_public_key
  ) {
    throw new TargetResolutionError(
      'CONSUMED_BUNDLE_MISMATCH',
      'Consumed prekey bundle does not match the trusted discovered device identity',
    );
  }
}

function decodeIdentity(encoded: string): Uint8Array {
  const identity = base64UrlToBytes(encoded);
  if (identity.length !== 32) throw new LocalStorageError('CORRUPT_STATE', 'Remote X25519 identity key must be 32 bytes');
  return identity;
}

function pairLock(localDeviceId: string, remoteDeviceId: string): string {
  return `crypto:${localDeviceId}:${remoteDeviceId}`;
}

async function persistRecipientSetCache(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  senderDeviceId: string,
  devices: readonly PublicPrekeyBundle[],
): Promise<void> {
  const value: CachedRecipientSet = {
    version: 1,
    chat_id: chatId,
    sender_device_id: senderDeviceId,
    devices: devices.map((device) => ({
      user_id: device.user_id,
      device_id: device.device_id,
      identity_public_key: device.identity_public_key,
    })),
  };
  await db.put('settings', { key: recipientSetCacheKey(chatId, senderDeviceId), kind: 'json', value } satisfies JsonSetting);
}

function recipientSetCacheKey(chatId: string, senderDeviceId: string): string {
  return `send-recipients:v1:${chatId}:${senderDeviceId}`;
}

function parseCachedRecipientSet(value: unknown): CachedRecipientSet | null {
  if (!value || typeof value !== 'object') return null;
  const candidate = value as Partial<CachedRecipientSet>;
  if (candidate.version !== 1 || typeof candidate.chat_id !== 'string' || typeof candidate.sender_device_id !== 'string' || !Array.isArray(candidate.devices)) return null;
  const devices: CachedRecipientDevice[] = [];
  const ids = new Set<string>();
  for (const entry of candidate.devices) {
    if (!entry || typeof entry !== 'object') return null;
    const device = entry as Partial<CachedRecipientDevice>;
    if (typeof device.user_id !== 'string' || typeof device.device_id !== 'string' || typeof device.identity_public_key !== 'string') return null;
    if (ids.has(device.device_id)) return null;
    ids.add(device.device_id);
    devices.push({ user_id: device.user_id, device_id: device.device_id, identity_public_key: device.identity_public_key });
  }
  return { version: 1, chat_id: candidate.chat_id, sender_device_id: candidate.sender_device_id, devices };
}
