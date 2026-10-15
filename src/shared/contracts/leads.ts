import { z } from 'zod';

const LeadDeviceSchema = z.object({
  device_id: z.string().uuid(),
  display_name: z.string().trim().min(1).max(120),
  crypto_identity_public_key: z.string().min(32).max(4096),
});

export const ClaimLeadRequestSchema = z.object({
  invitation_token: z.string().min(32).max(512),
  device: LeadDeviceSchema,
});

export const ClaimLeadResponseSchema = z.object({
  session_id: z.string().uuid(),
  user_id: z.string().uuid(),
  device_id: z.string().uuid(),
  chat_id: z.string().uuid(),
  device_state: z.literal('AUTHORIZED'),
});

export const CreateGuestAccountRequestSchema = z.object({
  display_name: z.string().trim().min(1).max(80),
  login_name: z.string().trim().min(3).max(64).regex(/^[A-Za-z0-9._-]+$/).optional(),
  password: z.string().min(15).max(256).optional(),
}).refine((value) => Boolean(value.login_name) === Boolean(value.password), {
  message: 'Login name and password must be provided together',
});

export const CreateCustomerAccessRequestSchema = z.object({});

export const SetCustomerPasswordRequestSchema = z.object({
  login_name: z.string().trim().min(3).max(64).regex(/^[A-Za-z0-9._-]+$/),
  password: z.string().min(15).max(256),
});

export const ClaimCustomerAccessRequestSchema = z.object({
  access_token: z.string().min(32).max(512),
  device: LeadDeviceSchema,
});

export const CreateGuestAccountResponseSchema = z.object({
  invitation_id: z.string().uuid(),
  customer_user_id: z.string().uuid(),
  chat_id: z.string().uuid(),
  login_name: z.string().nullable(),
  token: z.string().min(32).max(512),
  expires_at: z.string().datetime(),
  display_name: z.string().trim().min(1).max(80).nullable().default(null),
});

export const ClaimCustomerAccessResponseSchema = ClaimLeadResponseSchema;

export type ClaimLeadRequest = z.infer<typeof ClaimLeadRequestSchema>;
export type CreateGuestAccountRequest = z.infer<typeof CreateGuestAccountRequestSchema>;
export type ClaimCustomerAccessRequest = z.infer<typeof ClaimCustomerAccessRequestSchema>;
export type SetCustomerPasswordRequest = z.infer<typeof SetCustomerPasswordRequestSchema>;
