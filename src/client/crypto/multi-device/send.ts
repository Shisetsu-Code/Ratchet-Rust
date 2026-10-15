import type { IDBPDatabase } from 'idb';
import type { SendMessageRequest } from '../../../shared/contracts/messages';
import type { LocalDbSchema, PendingOutboxRecord } from '../../storage/schema';
import { prepareAtomicMultiDeviceMessage, type EstablishedAtomicTarget, normalizeAtomicTargets } from './atomic-send';

export type MultiDeviceTarget = Omit<EstablishedAtomicTarget, 'mode'>;

export type MultiDeviceSendInput = {
  chat_id: string;
  sender_user_id: string;
  sender_device_id: string;
  client_message_id: string;
  plaintext: Uint8Array;
  targets: readonly MultiDeviceTarget[];
  recovery_envelopes?: SendMessageRequest['recovery_envelopes'];
};

export async function prepareMultiDeviceRatchetMessage(
  db: IDBPDatabase<LocalDbSchema>,
  masterKey: CryptoKey,
  input: MultiDeviceSendInput,
): Promise<PendingOutboxRecord> {
  return prepareAtomicMultiDeviceMessage(db, masterKey, {
    chat_id: input.chat_id,
    sender_user_id: input.sender_user_id,
    sender_device_id: input.sender_device_id,
    client_message_id: input.client_message_id,
    plaintext: input.plaintext,
    initiator_identity: null,
    targets: input.targets.map((target) => ({ mode: 'established' as const, ...target })),
    recovery_envelopes: input.recovery_envelopes ?? [],
  });
}

export function normalizeTargets(senderDeviceId: string, targets: readonly MultiDeviceTarget[]): MultiDeviceTarget[] {
  return normalizeAtomicTargets(
    senderDeviceId,
    targets.map((target) => ({ mode: 'established' as const, ...target })),
  ).map((target) => ({
    session_id: target.session_id,
    recipient_user_id: target.recipient_user_id,
    recipient_device_id: target.recipient_device_id,
  }));
}
