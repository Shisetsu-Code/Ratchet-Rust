import { z } from 'zod';

export const BootstrapStatusResponseSchema = z.object({
  configured: z.boolean(),
  available: z.boolean(),
});

export type BootstrapStatusResponse = z.infer<typeof BootstrapStatusResponseSchema>;
