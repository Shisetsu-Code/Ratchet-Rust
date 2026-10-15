import { z } from 'zod';
import { apiFetch } from '../transport/api';

export const ChatSummarySchema = z.object({
  chat_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  created_at: z.string(),
  revision: z.number().int().nonnegative(),
  message_revision: z.number().int().nonnegative(),
  receipt_revision: z.number().int().nonnegative(),
  mutation_revision: z.number().int().nonnegative(),
  device_revision: z.number().int().nonnegative(),
  customer_user_id: z.string().uuid().nullable(),
  customer_has_account: z.boolean().nullable(),
  referred_by_user_id: z.string().uuid().nullable(),
  referred_by_display_name: z.string().nullable(),
  referred_by_staff_role: z.enum(['OWNER', 'ADMIN', 'OPERATOR']).nullable(),
  support_display_name: z.string().nullable().default(null),
  customer_display_name: z.string().nullable().default(null),
});

export const ChatParticipantSchema = z.object({
  user_id: z.string().uuid(),
  participant_role: z.enum(['ADMIN', 'CUSTOMER']),
  joined_at: z.string(),
});

export const ChatDetailSchema = ChatSummarySchema.omit({
  customer_user_id: true,
  customer_has_account: true,
  referred_by_user_id: true,
  referred_by_display_name: true,
  referred_by_staff_role: true,
  support_display_name: true,
  customer_display_name: true,
}).extend({
  participants: z.array(ChatParticipantSchema),
});

export type ChatSummary = z.infer<typeof ChatSummarySchema>;
export type ChatDetail = z.infer<typeof ChatDetailSchema>;

export async function listChats(): Promise<ChatSummary[]> {
  return apiFetch('/api/v1/chats', {}, (value) => z.object({ chats: z.array(ChatSummarySchema) }).parse(value).chats);
}

export async function getChatDetailHttp(chatId: string): Promise<ChatDetail> {
  return apiFetch(`/api/v1/chats/${encodeURIComponent(chatId)}`, {}, (value) => ChatDetailSchema.parse(value));
}
