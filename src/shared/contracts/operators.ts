import { z } from 'zod';

const DisplayNameSchema = z.string().trim().min(1).max(80);
const NewOperatorDeviceSchema = z.object({
  device_id: z.string().uuid(),
  display_name: z.string().trim().min(1).max(120),
  crypto_identity_public_key: z.string().min(32).max(4096),
});

export const CreateOperatorRequestSchema = z.object({
  workspace_id: z.string().uuid(),
  display_name: DisplayNameSchema,
});

export const OperatorRecordSchema = z.object({
  user_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  staff_role: z.enum(['OWNER', 'ADMIN', 'OPERATOR']),
  display_name: DisplayNameSchema,
  login_name: z.string().nullable(),
  access_mode: z.literal('LINK'),
  created_at: z.string().datetime(),
  revoked_at: z.string().datetime().nullable(),
  active_device_count: z.number().int().nonnegative(),
  pending_access_grant_count: z.number().int().nonnegative(),
  last_seen_at: z.string().datetime().nullable(),
});

export const ListOperatorsResponseSchema = z.object({
  workspace_id: z.string().uuid(),
  can_manage: z.boolean(),
  operators: z.array(OperatorRecordSchema),
});

export const CreateOperatorResponseSchema = OperatorRecordSchema;

export const OperatorAccessGrantSchema = z.object({
  grant_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  operator_user_id: z.string().uuid(),
  created_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  claimed_at: z.string().datetime().nullable(),
  claimed_device_id: z.string().uuid().nullable(),
  revoked_at: z.string().datetime().nullable(),
});

export const CreateOperatorAccessGrantResponseSchema = OperatorAccessGrantSchema.extend({
  token: z.string().min(32).max(512),
});

export const ListOperatorAccessGrantsResponseSchema = z.object({
  grants: z.array(OperatorAccessGrantSchema),
});

export const ClaimOperatorAccessRequestSchema = z.object({
  access_token: z.string().min(32).max(512),
  device: NewOperatorDeviceSchema,
});

export const ClaimOperatorAccessResponseSchema = z.object({
  session_id: z.string().min(1),
  user_id: z.string().uuid(),
  device_id: z.string().uuid(),
  device_state: z.literal('AUTHORIZED'),
});

export type CreateOperatorRequest = z.infer<typeof CreateOperatorRequestSchema>;
export type OperatorRecord = z.infer<typeof OperatorRecordSchema>;
export type OperatorAccessGrant = z.infer<typeof OperatorAccessGrantSchema>;
export type ClaimOperatorAccessRequest = z.infer<typeof ClaimOperatorAccessRequestSchema>;
