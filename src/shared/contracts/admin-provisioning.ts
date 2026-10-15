import { z } from 'zod';

const Base64Url32Schema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

export const AdminProvisioningPrepareRequestSchema = z.object({
  bootstrap_token: z.string().min(32).max(512),
  owner_key_id: z.string().uuid(),
});

export const AdminProvisioningCompleteRequestSchema = z.object({
  bootstrap_token: z.string().min(32).max(512),
  challenge_id: z.string().uuid(),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  key_id: z.string().uuid(),
  public_key: Base64Url32Schema,
  login_name: z.string().trim().min(3).max(64).regex(/^[A-Za-z0-9._-]+$/),
  master_password: z.string().min(15).max(256),
});

export const AdminProvisioningResponseSchema = z.object({
  user_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  key_id: z.string().uuid(),
  role: z.literal('ADMIN'),
});
