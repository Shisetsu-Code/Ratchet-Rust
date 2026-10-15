import { z } from 'zod';

export const DeviceViewSchema = z.object({
  device_id: z.string().uuid(),
  display_name: z.string(),
  created_at: z.string().datetime(),
  authorized_at: z.string().datetime().nullable(),
  revoked_at: z.string().datetime().nullable(),
  last_seen_at: z.string().datetime().nullable(),
});
