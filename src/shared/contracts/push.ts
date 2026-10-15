import { z } from 'zod';

const Base64UrlSchema = z.string().regex(/^[A-Za-z0-9_-]+$/);
export const PushSubscriptionSchema = z.object({
  endpoint: z.string().url().max(4096).refine((value) => new URL(value).protocol === 'https:', 'Push endpoint must use HTTPS'),
  expirationTime: z.number().nonnegative().nullable().optional(),
  keys: z.object({
    p256dh: Base64UrlSchema.min(80).max(100),
    auth: Base64UrlSchema.min(20).max(32),
  }),
});
export const PushConfigResponseSchema = z.object({
  enabled: z.boolean(),
  application_server_key: Base64UrlSchema.nullable(),
});
export const PushRegistrationResponseSchema = z.object({
  subscription_id: z.string().uuid(),
});
export type PushSubscriptionPayload = z.infer<typeof PushSubscriptionSchema>;
export type PushConfigResponse = z.infer<typeof PushConfigResponseSchema>;
