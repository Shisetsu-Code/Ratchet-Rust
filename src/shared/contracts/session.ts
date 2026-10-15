import { z } from 'zod';

export const CurrentSessionResponseSchema = z.object({
  session_id: z.string().min(1),
  user_id: z.string().uuid(),
  role: z.enum(['ADMIN', 'CUSTOMER']),
  device_id: z.string().uuid(),
  device_authorized: z.boolean(),
  webauthn_verified_at: z.string().datetime().nullable(),
  authenticator_verified_at: z.string().datetime().nullable(),
  workspace_ids: z.array(z.string().uuid()),
  staff_memberships: z.array(z.object({
    workspace_id: z.string().uuid(),
    staff_role: z.enum(['OWNER', 'ADMIN', 'OPERATOR']),
    display_name: z.string().trim().min(1).max(80),
  })),
});

export const UpdateStaffDisplayNameRequestSchema = z.object({
  workspace_id: z.string().uuid(),
  display_name: z.string().trim().min(1).max(80),
});
export const UpdateStaffDisplayNameResponseSchema = UpdateStaffDisplayNameRequestSchema;

export type CurrentSessionResponse = z.infer<typeof CurrentSessionResponseSchema>;
