import { z } from 'zod';

export const UserRoleSchema = z.enum(['ADMIN', 'CUSTOMER']);
export const UserStatusSchema = z.enum(['INVITED', 'ACTIVE', 'SUSPENDED']);
export const DeviceStatusSchema = z.enum(['PENDING', 'AUTHORIZED', 'REVOKED']);

export const SessionViewSchema = z.object({
  session_id: z.string().uuid(),
  device_id: z.string().uuid(),
  created_at: z.string().datetime(),
  last_seen_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  revoked_at: z.string().datetime().nullable(),
});
