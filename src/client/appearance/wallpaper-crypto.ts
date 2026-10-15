import type { IDBPDatabase } from 'idb';
import type { CurrentSessionResponse } from '../../shared/contracts/session';
import {
  WALLPAPER_CRYPTO_PROTOCOL,
  WALLPAPER_CRYPTO_VERSION,
  wallpaperImageAad,
  wallpaperKeyEnvelopeAad,
  wallpaperManifestSigningBytes,
  type ChatWallpaperResponse,
  type WallpaperKeyEnvelope,
  type WallpaperManifest,
  type WallpaperRecipientDevice,
  type WallpaperRecipientSetResponse,
} from '../../shared/contracts/wallpaper';
import { uuidv7 } from '../../shared/ids/uuidv7';
import type { LocalDbSchema } from '../storage/schema';
import { validateWallpaperFile } from '../attachments/policy';
import {
  hkdfSha256,
  randomBytes,
  sha256Digest,
  wipe,
  x25519PublicKey,
  x25519SharedSecret,
  xchachaOpen,
  xchachaSeal,
} from '../crypto/primitives';
import { disposeDeviceIdentity, loadDeviceIdentity } from '../crypto/key-vault/identity';
import { base64UrlToBytes, bytesToBase64Url } from '../crypto/local-state/base64url';
import { discoverPrekeyBundles } from '../crypto/prekeys/api';
import {
  ensureSelfDeviceTrust,
  verifyAndPersistTrustedDeviceSet,
} from '../crypto/trust/device-trust';
import { xed25519Sign, xed25519Verify } from '../crypto/xeddsa';

const WRAP_KDF_INFO = new TextEncoder().encode('RatchetSecureSupport/WallpaperKeyWrap/kdf/v1');

export type PreparedWallpaperCrypto = {
  wallpaperId: string;
  ciphertext: Uint8Array;
  manifest: WallpaperManifest;
  signatureB64Url: string;
  envelopes: WallpaperKeyEnvelope[];
};

export type OpenedWallpaperCrypto = {
  file: File;
  contentKey: Uint8Array;
};

export async function prepareEncryptedWallpaper(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  recipients: WallpaperRecipientSetResponse,
  file: File,
): Promise<PreparedWallpaperCrypto> {
  if (!recipients.can_distribute || recipients.owner_admin_user_id !== session.user_id) {
    throw new Error('Current account cannot distribute this wallpaper');
  }

  const contentType = await validateWallpaperFile(file);
  const wallpaperId = uuidv7();
  const identity = await loadDeviceIdentity(db, session.device_id);
  let plaintext: Uint8Array | undefined;
  let contentKey: Uint8Array | undefined;
  let imageNonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let digest: Uint8Array | undefined;
  let signingBytes: Uint8Array | undefined;
  let signature: Uint8Array | undefined;

  try {
    await verifyWallpaperRecipients(db, session, recipients.devices, identity.publicKeyEncoded);

    contentKey = randomBytes(32);
    imageNonce = randomBytes(24);
    plaintext = new Uint8Array(await file.arrayBuffer());
    const imageAad = wallpaperImageAad({
      wallpaper_id: wallpaperId,
      workspace_id: recipients.workspace_id,
      owner_admin_user_id: recipients.owner_admin_user_id,
      content_type: contentType,
    });
    try {
      ciphertext = xchachaSeal(contentKey, plaintext, imageAad, imageNonce).ciphertext;
    } finally {
      wipe(imageAad);
    }
    digest = sha256Digest(ciphertext);

    const manifest: WallpaperManifest = {
      protocol: WALLPAPER_CRYPTO_PROTOCOL,
      version: WALLPAPER_CRYPTO_VERSION,
      wallpaper_id: wallpaperId,
      workspace_id: recipients.workspace_id,
      owner_admin_user_id: recipients.owner_admin_user_id,
      signer_device_id: session.device_id,
      content_type: contentType,
      image_nonce_b64url: bytesToBase64Url(imageNonce),
      ciphertext_sha256_b64url: bytesToBase64Url(digest),
    };
    signingBytes = wallpaperManifestSigningBytes(manifest);
    signature = await xed25519Sign(identity.keyPair.privateKey, signingBytes);
    const envelopes = await createWallpaperKeyEnvelopes(contentKey, manifest, recipients.devices);

    return {
      wallpaperId,
      ciphertext: ciphertext.slice(),
      manifest,
      signatureB64Url: bytesToBase64Url(signature),
      envelopes,
    };
  } finally {
    disposeDeviceIdentity(identity);
    plaintext?.fill(0);
    contentKey?.fill(0);
    imageNonce?.fill(0);
    ciphertext?.fill(0);
    digest?.fill(0);
    signingBytes?.fill(0);
    signature?.fill(0);
  }
}

export async function unwrapVerifiedWallpaperContentKey(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  chatId: string,
  descriptor: Extract<ChatWallpaperResponse, { kind: 'custom' }>,
): Promise<Uint8Array> {
  const envelope = descriptor.key_envelope;
  if (!envelope
    || envelope.recipient_user_id !== session.user_id
    || envelope.recipient_device_id !== session.device_id) {
    throw new Error('This device does not have a wallpaper key envelope yet');
  }

  await verifyWallpaperManifestSigner(db, chatId, descriptor.manifest, descriptor.signature_b64url);
  const identity = await loadDeviceIdentity(db, session.device_id);
  try {
    return unwrapWallpaperKey(identity.keyPair.privateKey, descriptor.manifest, envelope);
  } finally {
    disposeDeviceIdentity(identity);
  }
}

export async function openEncryptedWallpaper(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  chatId: string,
  descriptor: Extract<ChatWallpaperResponse, { kind: 'custom' }>,
  ciphertext: Uint8Array,
): Promise<OpenedWallpaperCrypto> {
  const contentKey = await unwrapVerifiedWallpaperContentKey(db, session, chatId, descriptor);
  let plaintext: Uint8Array | undefined;
  try {
    const digest = sha256Digest(ciphertext);
    try {
      if (!constantTimeEqual(digest, base64UrlToBytes(descriptor.manifest.ciphertext_sha256_b64url))) {
        throw new Error('Shared wallpaper ciphertext digest mismatch');
      }
    } finally {
      digest.fill(0);
    }

    const nonce = base64UrlToBytes(descriptor.manifest.image_nonce_b64url);
    const imageAad = wallpaperImageAad({
      wallpaper_id: descriptor.manifest.wallpaper_id,
      workspace_id: descriptor.manifest.workspace_id,
      owner_admin_user_id: descriptor.manifest.owner_admin_user_id,
      content_type: descriptor.manifest.content_type,
    });
    try {
      plaintext = xchachaOpen(contentKey, { nonce, ciphertext }, imageAad);
    } finally {
      wipe(nonce, imageAad);
    }

    const file = new File([plaintext.slice().buffer], 'wallpaper', { type: descriptor.manifest.content_type });
    const detected = await validateWallpaperFile(file);
    if (detected !== descriptor.manifest.content_type) {
      throw new Error('Shared wallpaper content type mismatch');
    }
    return { file, contentKey: contentKey.slice() };
  } finally {
    contentKey.fill(0);
    plaintext?.fill(0);
  }
}

export async function createMissingWallpaperKeyEnvelopes(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  recipients: WallpaperRecipientSetResponse,
  manifest: WallpaperManifest,
  contentKey: Uint8Array,
): Promise<WallpaperKeyEnvelope[]> {
  if (!recipients.can_distribute
    || recipients.workspace_id !== manifest.workspace_id
    || recipients.owner_admin_user_id !== manifest.owner_admin_user_id
    || recipients.current_wallpaper_id !== manifest.wallpaper_id) {
    return [];
  }
  const identity = await loadDeviceIdentity(db, session.device_id);
  try {
    await verifyWallpaperRecipients(db, session, recipients.devices, identity.publicKeyEncoded);
  } finally {
    disposeDeviceIdentity(identity);
  }
  const existing = new Set(recipients.enveloped_device_ids);
  return createWallpaperKeyEnvelopes(
    contentKey,
    manifest,
    recipients.devices.filter((device) => !existing.has(device.device_id)),
  );
}

async function verifyWallpaperRecipients(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  devices: readonly WallpaperRecipientDevice[],
  currentIdentityPublicKey: string,
): Promise<void> {
  const byUser = new Map<string, WallpaperRecipientDevice[]>();
  for (const device of devices) {
    const group = byUser.get(device.user_id) ?? [];
    group.push(device);
    byUser.set(device.user_id, group);
  }

  const own = byUser.get(session.user_id) ?? [];
  const current = own.find((device) => device.device_id === session.device_id);
  if (!current || current.identity_public_key !== currentIdentityPublicKey) {
    throw new Error('Current device is absent from wallpaper recipient set');
  }

  await ensureSelfDeviceTrust(db, session.user_id, session.device_id, currentIdentityPublicKey);
  const trustedDevices = new Map<string, { userId: string; identityPublicKey: string }>();
  for (const userId of byUser.keys()) {
    const trusted = await db.getAllFromIndex('trusted_peer_devices', 'by-user', userId);
    for (const record of trusted) {
      trustedDevices.set(record.device_id, {
        userId: record.user_id,
        identityPublicKey: record.identity_public_key,
      });
    }
  }
  assertWallpaperRecipientRootShape(devices, trustedDevices);

  for (const [userId, candidates] of byUser) {
    await verifyAndPersistTrustedDeviceSet(db, userId, candidates);
  }
}

export function assertWallpaperRecipientRootShape(
  devices: readonly WallpaperRecipientDevice[],
  trustedDevices: ReadonlyMap<string, { userId: string; identityPublicKey: string }>,
): void {
  const rootsByUser = new Map<string, WallpaperRecipientDevice[]>();
  const users = new Set<string>();
  for (const device of devices) {
    users.add(device.user_id);
    if (!device.device_certificate) {
      const roots = rootsByUser.get(device.user_id) ?? [];
      roots.push(device);
      rootsByUser.set(device.user_id, roots);
    }
  }

  for (const userId of users) {
    if (devices.filter(device => device.user_id === userId).every(device => device.account_authorized === true)) continue;
    const roots = rootsByUser.get(userId) ?? [];
    if (roots.length === 0) {
      const hasTrustedAnchor = [...trustedDevices.values()].some((trusted) => trusted.userId === userId);
      if (!hasTrustedAnchor) throw new Error('Wallpaper recipient identity has no trusted root');
      continue;
    }
    if (roots.length === 1) continue;

    const allPreviouslyPinned = roots.every((root) => {
      const trusted = trustedDevices.get(root.device_id);
      return trusted?.userId === userId && trusted.identityPublicKey === root.identity_public_key;
    });
    if (!allPreviouslyPinned) {
      throw new Error('Wallpaper recipient identity exposes an untrusted additional root');
    }
  }
}

async function verifyWallpaperManifestSigner(
  db: IDBPDatabase<LocalDbSchema>,
  chatId: string,
  manifest: WallpaperManifest,
  signatureB64Url: string,
): Promise<void> {
  const pinned = await db.get('trusted_peer_devices', manifest.signer_device_id);
  let signerIdentityPublicKey: string;
  if (pinned) {
    if (pinned.user_id !== manifest.owner_admin_user_id) {
      throw new Error('Pinned wallpaper signer belongs to another user');
    }
    signerIdentityPublicKey = pinned.identity_public_key;
  } else {
    const discovery = await discoverPrekeyBundles(manifest.owner_admin_user_id, chatId);
    if (discovery.user_id !== manifest.owner_admin_user_id) {
      throw new Error('Wallpaper signer discovery returned another user');
    }
    const existing = await db.getAllFromIndex('trusted_peer_devices', 'by-user', manifest.owner_admin_user_id);
    const trustedDevices = new Map(existing.map((record) => [
      record.device_id,
      { userId: record.user_id, identityPublicKey: record.identity_public_key },
    ]));
    assertWallpaperRecipientRootShape(discovery.devices, trustedDevices);
    await verifyAndPersistTrustedDeviceSet(db, manifest.owner_admin_user_id, discovery.devices);
    const signer = discovery.devices.find((device) => device.device_id === manifest.signer_device_id);
    if (!signer) throw new Error('Wallpaper signer device is unavailable and was never trusted locally');
    signerIdentityPublicKey = signer.identity_public_key;
  }

  const signingBytes = wallpaperManifestSigningBytes(manifest);
  const publicKey = base64UrlToBytes(signerIdentityPublicKey);
  const signature = base64UrlToBytes(signatureB64Url);
  try {
    if (!await xed25519Verify(publicKey, signingBytes, signature)) {
      throw new Error('Wallpaper manifest signature verification failed');
    }
  } finally {
    wipe(signingBytes, publicKey, signature);
  }
}

export function createWallpaperKeyEnvelopes(
  contentKey: Uint8Array,
  manifest: WallpaperManifest,
  devices: readonly WallpaperRecipientDevice[],
): WallpaperKeyEnvelope[] {
  const envelopes: WallpaperKeyEnvelope[] = [];
  for (const device of devices.slice().sort((a, b) => a.device_id.localeCompare(b.device_id))) {
    const recipientPublicKey = base64UrlToBytes(device.identity_public_key);
    const ephemeralPrivate = randomBytes(32);
    const ephemeralPublic = x25519PublicKey(ephemeralPrivate);
    let shared: Uint8Array | undefined;
    let salt: Uint8Array | undefined;
    let wrapKey: Uint8Array | undefined;
    const aad = wallpaperKeyEnvelopeAad({
      wallpaper_id: manifest.wallpaper_id,
      workspace_id: manifest.workspace_id,
      owner_admin_user_id: manifest.owner_admin_user_id,
      recipient_user_id: device.user_id,
      recipient_device_id: device.device_id,
    });
    try {
      shared = x25519SharedSecret(ephemeralPrivate, recipientPublicKey);
      salt = sha256Digest(aad);
      wrapKey = hkdfSha256(shared, salt, WRAP_KDF_INFO, 32);
      const sealed = xchachaSeal(wrapKey, contentKey, aad);
      try {
        envelopes.push({
          recipient_user_id: device.user_id,
          recipient_device_id: device.device_id,
          ephemeral_public_key_b64url: bytesToBase64Url(ephemeralPublic),
          nonce_b64url: bytesToBase64Url(sealed.nonce),
          wrapped_key_b64url: bytesToBase64Url(sealed.ciphertext),
        });
      } finally {
        wipe(sealed.nonce, sealed.ciphertext);
      }
    } finally {
      wipe(recipientPublicKey, ephemeralPrivate, ephemeralPublic, aad);
      shared?.fill(0);
      salt?.fill(0);
      wrapKey?.fill(0);
    }
  }
  return envelopes;
}

export function unwrapWallpaperKey(
  recipientPrivateKey: Uint8Array,
  manifest: WallpaperManifest,
  envelope: WallpaperKeyEnvelope,
): Uint8Array {
  const ephemeralPublic = base64UrlToBytes(envelope.ephemeral_public_key_b64url);
  const nonce = base64UrlToBytes(envelope.nonce_b64url);
  const wrapped = base64UrlToBytes(envelope.wrapped_key_b64url);
  const aad = wallpaperKeyEnvelopeAad({
    wallpaper_id: manifest.wallpaper_id,
    workspace_id: manifest.workspace_id,
    owner_admin_user_id: manifest.owner_admin_user_id,
    recipient_user_id: envelope.recipient_user_id,
    recipient_device_id: envelope.recipient_device_id,
  });
  let shared: Uint8Array | undefined;
  let salt: Uint8Array | undefined;
  let wrapKey: Uint8Array | undefined;
  try {
    shared = x25519SharedSecret(recipientPrivateKey, ephemeralPublic);
    salt = sha256Digest(aad);
    wrapKey = hkdfSha256(shared, salt, WRAP_KDF_INFO, 32);
    const contentKey = xchachaOpen(wrapKey, { nonce, ciphertext: wrapped }, aad);
    if (contentKey.length !== 32) {
      contentKey.fill(0);
      throw new Error('Invalid wallpaper content key length');
    }
    return contentKey;
  } finally {
    wipe(ephemeralPublic, nonce, wrapped, aad);
    shared?.fill(0);
    salt?.fill(0);
    wrapKey?.fill(0);
  }
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    right.fill(0);
    return false;
  }
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) diff |= left[index]! ^ right[index]!;
  right.fill(0);
  return diff === 0;
}
