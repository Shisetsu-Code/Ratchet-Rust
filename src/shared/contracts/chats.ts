import { z } from 'zod';

export const ChatParticipantSchema = z.object({
  user_id: z.string().uuid(),
  participant_role: z.enum(['ADMIN', 'CUSTOMER']),
  joined_at: z.string().datetime(),
});

export const ChatDetailResponseSchema = z.object({
  chat_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  created_at: z.string().datetime(),
  revision: z.number().int().nonnegative(),
  message_revision: z.number().int().nonnegative(),
  receipt_revision: z.number().int().nonnegative(),
  mutation_revision: z.number().int().nonnegative(),
  device_revision: z.number().int().nonnegative(),
  participants: z.array(ChatParticipantSchema).min(1),
});

export type ChatParticipant = z.infer<typeof ChatParticipantSchema>;
export type ChatDetailResponse = z.infer<typeof ChatDetailResponseSchema>;
