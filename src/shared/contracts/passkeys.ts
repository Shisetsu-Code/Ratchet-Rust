import { z } from 'zod';

const WebAuthnResponseSchema = z.object({
  id: z.string().min(1),
  rawId: z.string().min(1),
  type: z.literal('public-key'),
  response: z.record(z.string(), z.unknown()),
  clientExtensionResults: z.record(z.string(), z.unknown()).optional(),
  authenticatorAttachment: z.string().nullable().optional(),
}).passthrough();

export const AccessRegistrationOptionsRequestSchema = z.object({
  access_token: z.string().min(32),
  device_name: z.string().trim().min(1).max(80),
  crypto_identity_public_key: z.string().min(16).max(8192),
});

export const AccessRegistrationVerifyRequestSchema = z.object({
  challenge_id: z.string().uuid(),
  response: WebAuthnResponseSchema,
});

export const AuthenticationVerifyRequestSchema = z.object({
  challenge_id: z.string().uuid(),
  response: WebAuthnResponseSchema,
  device: z.discriminatedUnion('mode', [
    z.object({ mode: z.literal('existing'), device_id: z.string().uuid() }),
    z.object({
      mode: z.literal('new'),
      device_id: z.string().uuid(),
      display_name: z.string().trim().min(1).max(80),
      crypto_identity_public_key: z.string().min(16).max(8192),
    }),
  ]),
});

export const ReauthenticationVerifyRequestSchema = z.object({
  challenge_id: z.string().uuid(),
  response: WebAuthnResponseSchema,
});
