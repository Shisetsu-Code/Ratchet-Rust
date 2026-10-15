import type { IDBPDatabase } from 'idb';
import type { SendMessageRequest } from '../../../shared/contracts/messages';
import type { LocalDbSchema, PendingOutboxRecord } from '../../storage/schema';
import type { PqXdhPublicBundle, X25519KeyPair } from '../pqxdh/types';
import { prepareAtomicMultiDeviceMessage } from './atomic-send';

export type NewPairwiseTarget = {
  session_id: string;
  recipient_user_id: string;
  recipient_device_id: string;
  bundle: PqXdhPublicBundle;
};

export type BootstrapMultiDeviceSendInput = {
  chat_id: string;
  sender_user_id: string;
  sender_device_id: string;
  client_message_id: string;
  plaintext: Uint8Array;
  initiator_identity: X25519KeyPair;
  targets: readonly NewPairwiseTarget[];
  recovery_envelopes?: SendMessageRequest['recovery_envelopes'];
};

export async function prepareNewMultiDevicePrekeyMessage(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  input: BootstrapMultiDeviceSendInput,
): Promise<PendingOutboxRecord> {
  return prepareAtomicMultiDeviceMessage(db, masterKey, {
    chat_id: input.chat_id,
    sender_user_id: input.sender_user_id,
    sender_device_id: input.sender_device_id,
    client_message_id: input.client_message_id,
    plaintext: input.plaintext,
    initiator_identity: input.initiator_identity,
    targets: input.targets.map((target) => ({ mode: 'bootstrap' as const, ...target })),
    recovery_envelopes: input.recovery_envelopes ?? [],
  });
}
