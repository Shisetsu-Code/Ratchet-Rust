import type { IDBPDatabase } from 'idb';
import type { CryptoSessionRecord, LeaseSetting, LocalDbSchema } from '../../storage/schema';
import { LocalStorageError, normalizeStorageError } from '../../storage/errors';
import { assertLeaseRecord, withCryptoLock } from '../../storage/locks';
import type { DoubleRatchetState } from '../double-ratchet/types';
import { wipeRatchetState } from '../double-ratchet/state';
import { sessionStateAad } from './aad';
import { deserializeRatchetCore, serializeRatchetCore } from './ratchet-codec';
import { loadSkippedMessageKeys, wrapSkippedMessageKeys } from './skipped-store';
import { unwrapLocalSecret, wrapLocalSecret } from './wrapping';

export type EstablishedRatchetSession = {
  session_id: string;
  local_device_id: string;
  remote_device_id: string;
  remote_identity_public_key: Uint8Array;
  pqxdh_associated_data: Uint8Array;
  state: DoubleRatchetState;
};

export async function persistEstablishedRatchetSession(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  input: EstablishedRatchetSession,
): Promise<CryptoSessionRecord> {
  requireIdentityKey(input.remote_identity_public_key);
  const lockName = `crypto:${input.local_device_id}:${input.remote_device_id}`;
  return withCryptoLock(db, lockName, async (fence) => {
    const plaintext = serializeRatchetCore(input.state);
    let wrapped: Awaited<ReturnType<typeof wrapLocalSecret>>;
    let skipped: Awaited<ReturnType<typeof wrapSkippedMessageKeys>>;
    try {
      [wrapped, skipped] = await Promise.all([
        wrapLocalSecret(masterKey, plaintext, sessionStateAad(input.session_id, input.local_device_id, input.remote_device_id)),
        wrapSkippedMessageKeys(masterKey, input.session_id, input.state.skipped),
      ]);
    } finally {
      plaintext.fill(0);
    }
    const now = new Date().toISOString();
    const record: CryptoSessionRecord = {
      session_id: input.session_id,
      local_device_id: input.local_device_id,
      remote_device_id: input.remote_device_id,
      remote_identity_public_key: input.remote_identity_public_key.slice(),
      lock_name: lockName,
      protocol: 'secure-messaging',
      protocol_version: 1,
      pqxdh_associated_data: input.pqxdh_associated_data.slice(),
      establishment_state: 'ESTABLISHED',
      state_ciphertext: wrapped.ciphertext,
      state_nonce: wrapped.nonce,
      state_version: 1,
      updated_at: now,
    };

    try {
      const tx = db.transaction(['sessions', 'skipped_message_keys', 'settings'], 'readwrite');
      if (fence.kind === 'lease') {
        const stored = await tx.objectStore('settings').get(fence.lease_key);
        const lease = stored?.kind === 'lease' ? stored as LeaseSetting : undefined;
        assertLeaseRecord(lease, fence);
      }
      if (await tx.objectStore('sessions').get(input.session_id)) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Established ratchet session already exists');
      }
      if (await tx.objectStore('sessions').index('by-lock-name').get(lockName)) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Pairwise ratchet session already exists');
      }
      await tx.objectStore('sessions').put(record);
      for (const entry of skipped) await tx.objectStore('skipped_message_keys').put(entry);
      await tx.done;
      return record;
    } catch (error) {
      throw normalizeStorageError(error);
    }
  });
}

export async function loadRatchetState(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  record: CryptoSessionRecord,
): Promise<DoubleRatchetState> {
  const aad = sessionStateAad(record.session_id, record.local_device_id, record.remote_device_id);
  const plaintext = await unwrapLocalSecret(masterKey, { nonce: record.state_nonce, ciphertext: record.state_ciphertext }, aad);
  try {
    const skipped = await loadSkippedMessageKeys(db, masterKey, record.session_id);
    return deserializeRatchetCore(plaintext, skipped);
  } finally {
    plaintext.fill(0);
  }
}

export async function wrapRatchetCore(
  masterKey: CryptoKey,
  record: Pick<CryptoSessionRecord, 'session_id' | 'local_device_id' | 'remote_device_id'>,
  state: DoubleRatchetState,
): Promise<{ state_ciphertext: Uint8Array; state_nonce: Uint8Array }> {
  const plaintext = serializeRatchetCore(state);
  try {
    const wrapped = await wrapLocalSecret(
      masterKey,
      plaintext,
      sessionStateAad(record.session_id, record.local_device_id, record.remote_device_id),
    );
    return { state_ciphertext: wrapped.ciphertext, state_nonce: wrapped.nonce };
  } finally {
    plaintext.fill(0);
  }
}

export function assertEstablishedRatchetSession(record: CryptoSessionRecord): void {
  if (record.establishment_state !== 'ESTABLISHED') {
    throw new LocalStorageError('CORRUPT_STATE', 'Pairwise ratchet first message is not durably accepted yet');
  }
  if (!(record.pqxdh_associated_data instanceof Uint8Array) || record.pqxdh_associated_data.length === 0) {
    throw new LocalStorageError('CORRUPT_STATE', 'Pairwise ratchet is missing PQXDH associated data');
  }
  requireIdentityKey(record.remote_identity_public_key);
}

export function assertRemoteIdentityPinned(record: CryptoSessionRecord, remoteIdentityPublicKey: Uint8Array): void {
  requireIdentityKey(remoteIdentityPublicKey);
  requireIdentityKey(record.remote_identity_public_key);
  let different = 0;
  for (let index = 0; index < remoteIdentityPublicKey.length; index += 1) {
    different |= remoteIdentityPublicKey[index]! ^ record.remote_identity_public_key[index]!;
  }
  if (different !== 0) {
    throw new LocalStorageError('CORRUPT_STATE', 'Remote device identity key changed for an established pairwise session');
  }
}

export function disposeRatchetState(state: DoubleRatchetState | undefined): void {
  if (state) wipeRatchetState(state);
}

function requireIdentityKey(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new LocalStorageError('CORRUPT_STATE', 'Remote device identity key must be 32 bytes');
  }
}
