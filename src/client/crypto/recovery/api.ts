import {
  RecoveryEnvelopeResponseSchema,
  RecoveryKeyListResponseSchema,
  RecoveryKeyRecordSchema,
  RecoveryRecipientSetResponseSchema,
  type RecoveryEnvelopeResponse,
  type RecoveryKeyRecord,
  type RecoveryRecipientSetResponse,
  type RecoveryKeyAttestation,
} from '../../../shared/contracts/recovery';
import { apiFetch } from '../../transport/api';

export async function registerAccountRecoveryPublicKey(attestation: RecoveryKeyAttestation): Promise<RecoveryKeyRecord> {
  return apiFetch(
    '/api/v1/crypto/recovery/keys',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(attestation),
    },
    (value) => RecoveryKeyRecordSchema.parse(value),
    { retryMode: 'idempotent' },
  );
}

export async function listAccountRecoveryKeys(): Promise<RecoveryKeyRecord[]> {
  return apiFetch(
    '/api/v1/crypto/recovery/keys',
    {},
    (value) => RecoveryKeyListResponseSchema.parse(value).recovery_keys,
  );
}

export async function getRecoveryRecipientsHttp(chatId: string): Promise<RecoveryRecipientSetResponse> {
  return apiFetch(
    `/api/v1/crypto/recovery/recipients?chat_id=${encodeURIComponent(chatId)}`,
    {},
    (value) => RecoveryRecipientSetResponseSchema.parse(value),
  );
}

export async function getRecoveryEnvelopeHttp(
  chatId: string,
  messageId: string,
  recoveryKeyId: string,
): Promise<RecoveryEnvelopeResponse> {
  return apiFetch(
    `/api/v1/crypto/recovery/envelopes/${encodeURIComponent(messageId)}?chat_id=${encodeURIComponent(chatId)}&recovery_key_id=${encodeURIComponent(recoveryKeyId)}`,
    {},
    (value) => RecoveryEnvelopeResponseSchema.parse(value),
  );
}
