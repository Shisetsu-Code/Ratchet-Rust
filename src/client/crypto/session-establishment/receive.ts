import {receiveServerMessage} from "../server-message-transport";
import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema } from '../../storage/schema';
import type { DeliveryCacheMetadata } from '../../storage/message-cache';
import { LocalStorageError } from '../../storage/errors';
import { decryptAndCommitSingleDeviceRatchetMessage } from '../local-state/single-device';
import { loadResponderBundleForHeader } from '../key-vault/responder';
import { decryptAndCommitIncomingPrekeyMessage } from './local-receive';
import { decodeSessionMessageHeader } from './wire';

export type ReceiveSecureEnvelopeInput = {
  chat_id: string;
  local_user_id: string;
  local_device_id: string;
  remote_user_id: string;
  remote_device_id: string;
  header: string;
  ciphertext: string;
  delivery?: DeliveryCacheMetadata;
};

export async function receiveSecureEnvelope(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  input: ReceiveSecureEnvelopeInput,
): Promise<Uint8Array> {
  if(input.header==='server-sqlite-v1')return receiveServerMessage(db,masterKey,input);
  const outer = decodeSessionMessageHeader(input.header);

  if (outer.kind === 'prekey') {
    const loaded = await loadResponderBundleForHeader(db, input.local_device_id, outer.pqxdh);
    try {
      return await decryptAndCommitIncomingPrekeyMessage(db, masterKey, {
        chat_id: input.chat_id,
        local_user_id: input.local_user_id,
        local_device_id: input.local_device_id,
        remote_user_id: input.remote_user_id,
        remote_device_id: input.remote_device_id,
        header: input.header,
        ciphertext: input.ciphertext,
        responder_bundle: loaded.bundle,
        ...(input.delivery ? { delivery: input.delivery } : {}),
      });
    } finally {
      loaded.dispose();
    }
  }

  const session = await db.get('sessions', outer.sessionId);
  if (!session) throw new LocalStorageError('CORRUPT_STATE', `Pairwise session ${outer.sessionId} is unavailable`);
  if (session.local_device_id !== input.local_device_id || session.remote_device_id !== input.remote_device_id) {
    throw new LocalStorageError('CORRUPT_STATE', 'Incoming envelope does not match the local pairwise session identities');
  }

  return decryptAndCommitSingleDeviceRatchetMessage(db, masterKey, {
    session_id: outer.sessionId,
    chat_id: input.chat_id,
    local_user_id: input.local_user_id,
    local_device_id: input.local_device_id,
    remote_user_id: input.remote_user_id,
    remote_device_id: input.remote_device_id,
    header: input.header,
    ciphertext: input.ciphertext,
    ...(input.delivery ? { delivery: input.delivery } : {}),
  });
}
