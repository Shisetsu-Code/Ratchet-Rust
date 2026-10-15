import { wipe } from '../primitives';
import { generateRecoveryKeyPair } from './archive';
import { listAccountRecoveryKeys, registerAccountRecoveryPublicKey } from './api';
import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema } from '../../storage/schema';
import { loadDeviceIdentity, disposeDeviceIdentity } from '../key-vault/identity';
import { recoveryKeySigningBytes, type RecoveryKeyAttestation } from '../../../shared/contracts/recovery';
import { bytesToBase64Url } from '../local-state/base64url';
import { xed25519Sign } from '../xeddsa';
import { ensureSelfDeviceTrust } from '../trust/device-trust';
import { recoveryPinKey, verifyAndPinRecoveryRecipient } from './trust';

export type GeneratedAccountRecoveryKey = {
  recovery_key_id: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
};

/**
 * Generates recovery-card material locally and registers only its public key.
 * The returned private key is intentionally not persisted by this helper and
 * must never be sent to the Worker.
 */
export async function generateAndRegisterAccountRecoveryKey(db: IDBPDatabase<LocalDbSchema>, userId: string, deviceId: string, savePreparedCard: (key: GeneratedAccountRecoveryKey) => void | Promise<void>): Promise<GeneratedAccountRecoveryKey> {
  const identity = await loadDeviceIdentity(db, deviceId);
  const pair = generateRecoveryKeyPair();
  try {
    await ensureSelfDeviceTrust(db, userId, deviceId, identity.publicKeyEncoded);
    const keys = await listAccountRecoveryKeys();
    const current = keys.find(key => key.active);
    const pin = await db.get('settings', recoveryPinKey(userId));
    if (current && current.user_id !== userId) throw new Error('Recovery registry returned another account');
    if (pin && !current?.attestation) {
      throw new Error('Pinned recovery identity is missing from the registry');
    }
    if (current?.attestation) {
      const signer = await db.get('trusted_peer_devices', current.attestation.signer_device_id);
      if (pin || signer) {
        await verifyAndPinRecoveryRecipient(db, { ...current, proof_chain: keys.flatMap(key => key.attestation ? [key.attestation] : []) });
      }
      // A replacement browser may have no pin or trusted historical signer.
      // This explicit account rotation never trusts or encrypts to that old key:
      // it signs fresh local material using SELF. Existing peers still require
      // manual root rotation and enforce their own pinned generation continuity.
    }
    const payload: Omit<RecoveryKeyAttestation, 'signature'> = {
      protocol: 'secure-recovery-key', version: 1, recovery_key_id: crypto.randomUUID(), user_id: userId,
      public_key: bytesToBase64Url(pair.publicKey), generation: (current?.attestation?.generation ?? 0) + 1,
      predecessor_key_id: current?.recovery_key_id ?? null, created_at: new Date().toISOString(), signer_device_id: deviceId,
    };
    const proof = { ...payload, signature: bytesToBase64Url(await xed25519Sign(identity.keyPair.privateKey, recoveryKeySigningBytes(payload))) };
    // Save the private material before the remote key can become active. A lost
    // acknowledgement must not leave the account using an unrecoverable key.
    await savePreparedCard({ recovery_key_id: proof.recovery_key_id, privateKey: pair.privateKey, publicKey: pair.publicKey });
    const registered = await registerAccountRecoveryPublicKey(proof);
    await verifyAndPinRecoveryRecipient(db, { ...registered, proof_chain: [proof] });
    return {
      recovery_key_id: registered.recovery_key_id,
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
    };
  } catch (error) {
    wipe(pair.privateKey, pair.publicKey);
    throw error;
  } finally {
    disposeDeviceIdentity(identity);
  }
}

export function disposeAccountRecoveryPrivateKey(privateKey: Uint8Array): void {
  wipe(privateKey);
}
