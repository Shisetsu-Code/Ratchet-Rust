import type { IDBPDatabase } from 'idb';
import type { SendMessageRequest } from '../../shared/contracts/messages';
import { LocalStorageError, normalizeStorageError } from './errors';
import { assertLeaseRecord, withCryptoLock, type CryptoFence } from './locks';
import type { CryptoSessionRecord, LeaseSetting, LocalDbSchema, PendingOutboxRecord } from './schema';

export type CryptoTransitionDraft = {
  next_session: Omit<CryptoSessionRecord, 'state_version' | 'updated_at'>;
  request: SendMessageRequest;
  encrypted_retry_material?: Uint8Array;
};

export type PrepareCryptoMessageInput = {
  session_id: string;
  local_device_id: string;
  remote_device_id: string;
  chat_id: string;
  client_message_id: string;
  sender_device_id: string;
};

export type CryptoTransitionBuilder = (
  current: CryptoSessionRecord | undefined,
) => Promise<CryptoTransitionDraft>;

export async function prepareEncryptedOutboxMessage(
  db: IDBPDatabase<LocalDbSchema>,
  input: PrepareCryptoMessageInput,
  build: CryptoTransitionBuilder,
  onCommitted?: (session: CryptoSessionRecord, outbox: PendingOutboxRecord) => void,
): Promise<PendingOutboxRecord> {
  const lockName = `crypto:${input.local_device_id}:${input.remote_device_id}`;
  return withCryptoLock(db, lockName, async (fence) => {
    const existing = await db.get('pending_outbox', input.client_message_id);
    if (existing) return existing;

    const snapshot = await db.get('sessions', input.session_id);
    validateSnapshot(snapshot, input, lockName);

    const draft = await build(snapshot);
    validateDraft(draft, input, lockName);

    const nextVersion = (snapshot?.state_version ?? 0) + 1;
    const now = new Date().toISOString();
    const nextSession: CryptoSessionRecord = {
      ...draft.next_session,
      state_version: nextVersion,
      updated_at: now,
    };
    const outbox: PendingOutboxRecord = {
      client_message_id: input.client_message_id,
      chat_id: input.chat_id,
      sender_device_id: input.sender_device_id,
      request: draft.request,
      ...(draft.encrypted_retry_material ? { encrypted_retry_material: draft.encrypted_retry_material } : {}),
      status: 'PENDING',
      attempts: 0,
      created_at: now,
      updated_at: now,
    };

    try {
      const tx = db.transaction(['sessions', 'pending_outbox', 'settings'], 'readwrite');
      if (fence.kind === 'lease') {
        const storedFence = await tx.objectStore('settings').get(fence.lease_key);
        const lease = storedFence?.kind === 'lease' ? storedFence as LeaseSetting : undefined;
        assertLeaseRecord(lease, fence);
      }

      const current = await tx.objectStore('sessions').get(input.session_id);
      if ((current?.state_version ?? 0) !== (snapshot?.state_version ?? 0)) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Session state changed before local commit');
      }
      if (await tx.objectStore('pending_outbox').get(input.client_message_id)) {
        tx.abort();
        throw new LocalStorageError('STATE_VERSION_CONFLICT', 'Outbox ID was committed concurrently');
      }

      await tx.objectStore('sessions').put(nextSession);
      await tx.objectStore('pending_outbox').put(outbox);
      await tx.done;
      onCommitted?.(nextSession, outbox);
      return outbox;
    } catch (error) {
      throw normalizeStorageError(error);
    }
  });
}

function validateSnapshot(snapshot: CryptoSessionRecord | undefined, input: PrepareCryptoMessageInput, lockName: string): void {
  if (!snapshot) return;
  if (
    snapshot.local_device_id !== input.local_device_id
    || snapshot.remote_device_id !== input.remote_device_id
    || snapshot.lock_name !== lockName
  ) {
    throw new LocalStorageError('CORRUPT_STATE', 'Stored session identity does not match the requested peer lock');
  }
}

function validateDraft(draft: CryptoTransitionDraft, input: PrepareCryptoMessageInput, lockName: string): void {
  if (draft.request.client_message_id !== input.client_message_id) {
    throw new LocalStorageError('CORRUPT_STATE', 'Crypto transition changed client_message_id');
  }
  if (
    draft.next_session.session_id !== input.session_id
    || draft.next_session.local_device_id !== input.local_device_id
    || draft.next_session.remote_device_id !== input.remote_device_id
    || draft.next_session.lock_name !== lockName
  ) {
    throw new LocalStorageError('CORRUPT_STATE', 'Crypto transition attempted to mutate immutable session identity');
  }
}

export function fenceDebugValue(fence: CryptoFence): string {
  return fence.kind === 'web-lock' ? fence.lock_name : `${fence.lock_name}:${fence.fencing_token}`;
}
