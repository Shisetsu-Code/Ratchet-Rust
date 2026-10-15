import { z } from 'zod';

export const InvitationKindSchema = z.enum(['ACCESS', 'REFERRAL']);

const CustomerLoginNameSchema = z.string()
  .trim()
  .min(3)
  .max(64)
  .regex(/^[A-Za-z0-9._-]+$/);

export const CreateInvitationRequestSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('ACCESS'),
    workspace_id: z.string().uuid(),
    login_name: CustomerLoginNameSchema,
    password: z.string().min(15).max(256),
  }),
  z.object({
    kind: z.literal('REFERRAL'),
    workspace_id: z.string().uuid(),
  }),
]);

export const CreateInvitationResponseSchema = z.object({
  invitation_id: z.string().uuid(),
  kind: InvitationKindSchema,
  token: z.string().min(32),
  expires_at: z.string().datetime().nullable(),
  customer_user_id: z.string().uuid().nullable(),
  chat_id: z.string().uuid().nullable(),
  login_name: z.string().nullable(),
});

export const ClaimReferralResponseSchema = z.object({
  invitation_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  chat_id: z.string().uuid(),
  duplicate: z.boolean(),
});
