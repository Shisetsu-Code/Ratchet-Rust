import type { IDBPDatabase } from 'idb';
import { RecoveryKeyAttestationSchema, recoveryKeySigningBytes, type RecoveryKeyAttestation, type RecoveryRecipient } from '../../../shared/contracts/recovery';
import type { JsonSetting, LocalDbSchema, TrustedPeerDeviceRecord } from '../../storage/schema';
import { withCryptoLock } from '../../storage/locks';
import { base64UrlToBytes } from '../local-state/base64url';
import { xed25519Verify } from '../xeddsa';

export type RecoveryPin = RecoveryKeyAttestation;
export const recoveryPinKey = (userId: string) => `crypto:recovery-pin:v1:${userId}`;

export function assertRecoveryRecipientCoverage(
  participantUserIds: readonly string[],
  pinnedUserIds: readonly string[],
  recipientUserIds: readonly string[],
): void {
  const participants = new Set(participantUserIds);
  const recipients = new Set(recipientUserIds);
  if (recipients.size !== recipientUserIds.length || recipientUserIds.some(userId => !participants.has(userId))) {
    throw new Error('Recovery recipients contain a duplicate or a non-participant');
  }
  if (pinnedUserIds.some(userId => participants.has(userId) && !recipients.has(userId))) {
    throw new Error('Pinned recovery identity is missing from the recipient set');
  }
}

export async function verifyRecoveryRecipient(
  recipient: RecoveryRecipient,
  pin: RecoveryPin | null,
  trustedDevices: readonly TrustedPeerDeviceRecord[],
): Promise<RecoveryPin> {
  const current = recipient.attestation;
  if (!current || current.user_id !== recipient.user_id || current.recovery_key_id !== recipient.recovery_key_id
    || current.public_key !== recipient.public_key) throw new Error('Recovery key attestation is missing or substituted');
  if (pin && (pin.user_id !== current.user_id || current.generation < pin.generation)) throw new Error('Recovery key rollback detected');
  RecoveryKeyAttestationSchema.parse(current);
  const currentSigner = trustedDevices.find(d => d.user_id === current.user_id && d.device_id === current.signer_device_id);
  if (!currentSigner || currentSigner.revoked_at) throw new Error('Recovery signer is not trusted or is revoked');
  if (!await xed25519Verify(base64UrlToBytes(currentSigner.identity_public_key), recoveryKeySigningBytes(current), base64UrlToBytes(current.signature))) {
    throw new Error('Recovery key signature verification failed');
  }
  const proofs = recipient.proof_chain.slice().sort((a, b) => a.generation - b.generation);
  if (proofs.some((p, i) => p.user_id !== current.user_id || (i > 0 && p.generation === proofs[i - 1]!.generation))) {
    throw new Error('Recovery history contains a foreign user or duplicate generation');
  }
  if (proofs.some(p => p.generation > current.generation)) throw new Error('Recovery key rollback detected');
  let previous = pin;
  // First observation anchors the current signed key to an already trusted device.
  const pending = pin ? proofs.filter(p => p.generation > pin.generation) : [current];
  for (const proof of pending) {
    RecoveryKeyAttestationSchema.parse(proof);
    if (previous && (proof.generation !== previous.generation + 1 || proof.predecessor_key_id !== previous.recovery_key_id)) {
      throw new Error('Recovery key continuity is broken');
    }
    const signer = trustedDevices.find(d => d.user_id === proof.user_id && d.device_id === proof.signer_device_id);
    if (!signer || signer.revoked_at) throw new Error('Recovery signer is not trusted or is revoked');
    if (!await xed25519Verify(base64UrlToBytes(signer.identity_public_key), recoveryKeySigningBytes(proof), base64UrlToBytes(proof.signature))) {
      throw new Error('Recovery key signature verification failed');
    }
    previous = proof;
  }
  if (!previous || new TextDecoder().decode(recoveryKeySigningBytes(previous)) !== new TextDecoder().decode(recoveryKeySigningBytes(current))) {
    throw new Error('Recovery key substituted at an existing generation');
  }
  return current;
}

export async function verifyAndPinRecoveryRecipient(db: IDBPDatabase<LocalDbSchema>, recipient: RecoveryRecipient, activeDeviceIds?: readonly string[]): Promise<void> {
  await withCryptoLock(db, recoveryPinKey(recipient.user_id), async () => {
    const key = recoveryPinKey(recipient.user_id);
    const before = await db.get('settings', key);
    const pin = before?.kind === 'json' ? RecoveryKeyAttestationSchema.parse(before.value) : null;
    const trusted = await db.getAllFromIndex('trusted_peer_devices', 'by-user', recipient.user_id);
    const next = await verifyRecoveryRecipient(recipient, pin, activeDeviceIds ? trusted.filter(d => activeDeviceIds.includes(d.device_id)) : trusted);
    const tx = db.transaction('settings', 'readwrite');
    if (JSON.stringify(await tx.store.get(key)) !== JSON.stringify(before)) {
      tx.abort();
      throw new Error('Recovery trust changed before commit');
    }
    await tx.store.put({ key, kind: 'json', value: next } satisfies JsonSetting);
    await tx.done;
  });
}
