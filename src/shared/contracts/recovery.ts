import { z } from 'zod';

export const RecoveryPublicKeySchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

export const RecoveryKeyAttestationSchema = z.object({
  protocol: z.literal('secure-recovery-key'),
  version: z.literal(1),
  recovery_key_id: z.string().uuid(),
  user_id: z.string().uuid(),
  public_key: RecoveryPublicKeySchema,
  generation: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  created_at: z.string().datetime(),
  predecessor_key_id: z.string().uuid().nullable(),
  signer_device_id: z.string().uuid(),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
}).strict();

export type RecoveryKeyAttestation = z.infer<typeof RecoveryKeyAttestationSchema>;
export const RegisterAccountRecoveryKeyRequestSchema = RecoveryKeyAttestationSchema;

export function recoveryKeySigningBytes(record: Omit<RecoveryKeyAttestation, 'signature'>): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    protocol: record.protocol, version: record.version, recovery_key_id: record.recovery_key_id,
    user_id: record.user_id, public_key: record.public_key, generation: record.generation,
    created_at: record.created_at, predecessor_key_id: record.predecessor_key_id,
    signer_device_id: record.signer_device_id,
  }));
}

export const RecoveryKeyRecordSchema = z.object({
  recovery_key_id: z.string().uuid(),
  user_id: z.string().uuid(),
  public_key: RecoveryPublicKeySchema,
  created_at: z.string().datetime(),
  revoked_at: z.string().datetime().nullable(),
  replaced_by_key_id: z.string().uuid().nullable(),
  active: z.boolean(),
  attestation: RecoveryKeyAttestationSchema.nullable(),
});

export const RecoveryKeyListResponseSchema = z.object({
  recovery_keys: z.array(RecoveryKeyRecordSchema),
});

export const RecoveryRecipientSchema = z.object({
  recovery_key_id: z.string().uuid(),
  user_id: z.string().uuid(),
  public_key: RecoveryPublicKeySchema,
  attestation: RecoveryKeyAttestationSchema.nullable(),
  proof_chain: z.array(RecoveryKeyAttestationSchema).max(128),
});

export const RecoveryRecipientSetResponseSchema = z.object({
  chat_id: z.string().uuid(),
  recovery_keys: z.array(RecoveryRecipientSchema).max(16),
});

export const RecoveryEnvelopeResponseSchema = z.object({
  message_id: z.string().uuid(),
  recovery_key_id: z.string().uuid(),
  wrapped_key: z.string().min(1),
  archive_ciphertext: z.string().min(1),
});

export type RecoveryKeyRecord = z.infer<typeof RecoveryKeyRecordSchema>;
export type RecoveryRecipient = z.infer<typeof RecoveryRecipientSchema>;
export type RecoveryRecipientSetResponse = z.infer<typeof RecoveryRecipientSetResponseSchema>;
export type RecoveryEnvelopeResponse = z.infer<typeof RecoveryEnvelopeResponseSchema>;
