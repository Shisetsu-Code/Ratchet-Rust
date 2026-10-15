import { z } from 'zod';

export const SupervisionParticipantSchema = z.object({
  user_id: z.string().uuid(),
  participant_role: z.enum(['ADMIN', 'CUSTOMER']),
  staff_role: z.enum(['OWNER', 'ADMIN', 'OPERATOR']).nullable(),
  display_name: z.string().trim().min(1).max(80),
  joined_at: z.string().datetime(),
});

export const SupervisionConversationSchema = z.object({
  chat_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  created_at: z.string().datetime(),
  message_count: z.number().int().nonnegative(),
  last_message_at: z.string().datetime().nullable(),
  last_sender_user_id: z.string().uuid().nullable(),
  referred_by_user_id: z.string().uuid().nullable(),
  referred_by_display_name: z.string().nullable(),
  referred_by_staff_role: z.enum(['ADMIN', 'OPERATOR']).nullable(),
  participants: z.array(SupervisionParticipantSchema).min(1),
});

export const SupervisionConversationsResponseSchema = z.object({
  conversations: z.array(SupervisionConversationSchema),
});

export type SupervisionParticipant = z.infer<typeof SupervisionParticipantSchema>;
export type SupervisionConversation = z.infer<typeof SupervisionConversationSchema>;
