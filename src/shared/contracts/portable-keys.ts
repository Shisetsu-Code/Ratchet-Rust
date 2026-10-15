import { z } from 'zod';

const Base64Url32Schema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const DeviceSchema = z.discriminatedUnion('mode', [
  z.object({ mode: z.literal('existing'), device_id: z.string().uuid() }),
  z.object({
    mode: z.literal('new'),
    device_id: z.string().uuid(),
    display_name: z.string().trim().min(1).max(120),
    crypto_identity_public_key: z.string().min(32).max(4096),
  }),
]);

export const PortableKeyBootstrapPrepareRequestSchema = z.object({
  bootstrap_token: z.string().min(32).max(512),
  key_id: z.string().uuid(),
  public_key: Base64Url32Schema,
});

export const PortableKeyBootstrapCompleteRequestSchema = z.object({
  bootstrap_token: z.string().min(32).max(512),
  challenge_id: z.string().uuid(),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  login_name: z.string().trim().min(3).max(64).regex(/^[A-Za-z0-9._-]+$/),
  master_password: z.string().min(15).max(256),
});

export const PortableKeyLoginPrepareRequestSchema = z.object({ key_id: z.string().uuid(), device: DeviceSchema });
export const PortableKeyLoginCompleteRequestSchema = z.object({
  challenge_id: z.string().uuid(),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
});
export const PortableKeyReauthPrepareRequestSchema = z.object({ key_id: z.string().uuid() });
export const PortableKeyReauthCompleteRequestSchema = PortableKeyLoginCompleteRequestSchema;

export const PortableKeyChallengeResponseSchema = z.object({
  challenge_id: z.string().uuid(),
  challenge: Base64Url32Schema,
  purpose: z.enum(['BOOTSTRAP', 'AUTHENTICATION', 'REAUTHENTICATION', 'ADMIN_PROVISIONING']),
  key_id: z.string().uuid(),
  origin: z.string().url(),
  device_id: z.string().uuid().optional(),
});

export const PortableKeyLoginResponseSchema = z.object({
  session_id: z.string().min(1),
  user_id: z.string().uuid(),
  device_id: z.string().uuid(),
  device_state: z.enum(['AUTHORIZED', 'PENDING']),
});

export const PortableKeyBootstrapResponseSchema = z.object({
  user_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  key_id: z.string().uuid(),
});

export type PortableKeyDevice = z.infer<typeof DeviceSchema>;
export type PortableKeyChallengeResponse = z.infer<typeof PortableKeyChallengeResponseSchema>;

export function portableKeySignatureMessage(input: {
  purpose: 'BOOTSTRAP' | 'AUTHENTICATION' | 'REAUTHENTICATION' | 'ADMIN_PROVISIONING';
  challenge_id: string;
  challenge: string;
  origin: string;
  key_id: string;
}): Uint8Array {
  return new TextEncoder().encode([
    'ratchet-portable-key-v1',
    input.purpose,
    input.challenge_id,
    input.challenge,
    input.origin,
    input.key_id,
  ].join('\n'));
}
