import { z } from 'zod';

const PublicKeyMaterialSchema = z.string().min(16).max(16_384);
const SignatureSchema = z.string().min(16).max(4_096);

export const PublishPrekeysRequestSchema = z.object({
  identity_public_key: PublicKeyMaterialSchema,
  signed_prekey: z.object({
    prekey_id: z.string().uuid(),
    public_key: PublicKeyMaterialSchema,
    signature: SignatureSchema,
  }),
  pq_last_resort_prekey: z.object({
    prekey_id: z.string().uuid(),
    public_key: PublicKeyMaterialSchema,
    signature: SignatureSchema,
  }),
  ec_one_time_prekeys: z.array(z.object({
    prekey_id: z.string().uuid(),
    public_key: PublicKeyMaterialSchema,
  })).max(100),
  pq_one_time_prekeys: z.array(z.object({
    prekey_id: z.string().uuid(),
    public_key: PublicKeyMaterialSchema,
    signature: SignatureSchema,
  })).max(100),
});

export const ConsumePrekeyRequestSchema = z.object({
  chat_id: z.string().uuid(),
  recipient_user_id: z.string().uuid(),
  recipient_device_id: z.string().uuid(),
});

export const PublicPrekeyBundleSchema = z.object({
  device_id: z.string().uuid(),
  user_id: z.string().uuid(),
  identity_public_key: PublicKeyMaterialSchema,
  signed_prekey: z.object({
    prekey_id: z.string().uuid(),
    public_key: PublicKeyMaterialSchema,
    signature: SignatureSchema,
  }),
  pq_last_resort_prekey: z.object({
    prekey_id: z.string().uuid(),
    public_key: PublicKeyMaterialSchema,
    signature: SignatureSchema,
  }),
  device_certificate: z.string().nullable(),
  account_authorized: z.literal(true).optional(),
});

export const ConsumedOneTimePrekeySchema = z.object({
  prekey_id: z.string().uuid(),
  public_key: PublicKeyMaterialSchema,
  signature: z.string().nullable(),
});

export const ConsumePrekeyResponseSchema = z.object({
  bundle: PublicPrekeyBundleSchema,
  ec_one_time_prekey: ConsumedOneTimePrekeySchema.nullable(),
  pq_one_time_prekey: ConsumedOneTimePrekeySchema.nullable(),
});

export const DeviceBundleDiscoveryResponseSchema = z.object({
  user_id: z.string().uuid(),
  devices: z.array(PublicPrekeyBundleSchema),
});

export const PrekeyStatusResponseSchema = z.object({
  device_id: z.string().uuid(),
  bundle_present: z.boolean(),
  ec_available: z.number().int().nonnegative(),
  pq_available: z.number().int().nonnegative(),
});

export type PublishPrekeysRequest = z.infer<typeof PublishPrekeysRequestSchema>;
export type ConsumePrekeyRequest = z.infer<typeof ConsumePrekeyRequestSchema>;
export type PublicPrekeyBundle = z.infer<typeof PublicPrekeyBundleSchema>;
export type ConsumePrekeyResponse = z.infer<typeof ConsumePrekeyResponseSchema>;
export type DeviceBundleDiscoveryResponse = z.infer<typeof DeviceBundleDiscoveryResponseSchema>;
export type PrekeyStatusResponse = z.infer<typeof PrekeyStatusResponseSchema>;
