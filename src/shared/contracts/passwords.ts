import { z } from 'zod';

export const PasswordLoginRequestSchema = z.object({
  login_name: z.string().trim().min(1).max(64),
  password: z.string().min(15).max(256),
  device: z.discriminatedUnion('mode', [
    z.object({
      mode: z.literal('existing'),
      device_id: z.string().uuid(),
    }),
    z.object({
      mode: z.literal('new'),
      device_id: z.string().uuid(),
      display_name: z.string().trim().min(1).max(120),
      crypto_identity_public_key: z.string().min(32).max(4096),
    }),
  ]),
});

const NewPasswordDeviceSchema = z.object({
  mode: z.literal('new'),
  device_id: z.string().uuid(),
  display_name: z.string().trim().min(1).max(120),
  crypto_identity_public_key: z.string().min(32).max(4096),
});

export const PasswordAccessActivationRequestSchema = z.object({
  access_token: z.string().min(32).max(512),
  login_name: z.string().trim().min(1).max(64),
  password: z.string().min(15).max(256),
  device: NewPasswordDeviceSchema,
});

export const PasswordReauthenticationRequestSchema = z.object({
  password: z.string().min(15).max(256),
});

export const PasswordLoginResponseSchema = z.object({
  session_id: z.string().min(1),
  user_id: z.string().uuid(),
  device_id: z.string().uuid(),
  device_state: z.enum(['AUTHORIZED', 'PENDING']),
});

export type PasswordLoginRequest = z.infer<typeof PasswordLoginRequestSchema>;
export type PasswordLoginResponse = z.infer<typeof PasswordLoginResponseSchema>;
export type PasswordAccessActivationRequest = z.infer<typeof PasswordAccessActivationRequestSchema>;
