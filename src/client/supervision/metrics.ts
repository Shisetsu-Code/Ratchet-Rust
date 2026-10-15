import type { SupervisionConversation } from '../../shared/contracts/supervision';

export type SupervisionMessage = {
  sender_user_id: string;
  created_at: string;
  text: string;
  attachment_count: number;
};

export type ConversationReview = {
  conversation: SupervisionConversation;
  customer_names: string[];
  staff_names: string[];
  message_count: number;
  last_message_at: string | null;
  last_message_preview: string;
  awaiting_team_reply: boolean;
  waiting_since: string | null;
  average_response_ms: number | null;
  completed_response_count: number;
};

export function evaluateConversation(
  conversation: SupervisionConversation,
  source: SupervisionMessage[],
): ConversationReview {
  const participants = new Map(conversation.participants.map((participant) => [participant.user_id, participant]));
  const messages = [...source].sort((left, right) => (
    left.created_at.localeCompare(right.created_at) || left.sender_user_id.localeCompare(right.sender_user_id)
  ));
  const responseTimes: number[] = [];
  let waitingSince: string | null = null;
  for (const message of messages) {
    const participant = participants.get(message.sender_user_id);
    if (participant?.participant_role === 'CUSTOMER') {
      waitingSince ??= message.created_at;
    } else if (waitingSince) {
      const elapsed = Date.parse(message.created_at) - Date.parse(waitingSince);
      if (Number.isFinite(elapsed) && elapsed >= 0) responseTimes.push(elapsed);
      waitingSince = null;
    }
  }
  const last = messages.at(-1);
  const preview = last
    ? last.text.trim() || (last.attachment_count === 1 ? '1 archivo adjunto' : `${last.attachment_count} archivos adjuntos`)
    : 'Sin mensajes todavía';
  return {
    conversation,
    customer_names: conversation.participants.filter((entry) => entry.participant_role === 'CUSTOMER').map((entry) => entry.display_name),
    staff_names: conversation.participants.filter((entry) => entry.participant_role === 'ADMIN').map((entry) => entry.display_name),
    message_count: messages.length,
    last_message_at: last?.created_at ?? null,
    last_message_preview: preview,
    awaiting_team_reply: waitingSince !== null,
    waiting_since: waitingSince,
    average_response_ms: responseTimes.length > 0
      ? Math.round(responseTimes.reduce((total, value) => total + value, 0) / responseTimes.length)
      : null,
    completed_response_count: responseTimes.length,
  };
}

export function evaluateConversationMetadata(conversation: SupervisionConversation): ConversationReview {
  const lastSender = conversation.last_sender_user_id
    ? conversation.participants.find((entry) => entry.user_id === conversation.last_sender_user_id)
    : undefined;
  const awaiting = lastSender?.participant_role === 'CUSTOMER';
  return {
    conversation,
    customer_names: conversation.participants.filter((entry) => entry.participant_role === 'CUSTOMER').map((entry) => entry.display_name),
    staff_names: conversation.participants.filter((entry) => entry.participant_role === 'ADMIN').map((entry) => entry.display_name),
    message_count: conversation.message_count,
    last_message_at: conversation.last_message_at,
    last_message_preview: lastSender ? `Último mensaje de ${lastSender.display_name}` : 'Sin mensajes todavía',
    awaiting_team_reply: awaiting,
    waiting_since: awaiting ? conversation.last_message_at : null,
    average_response_ms: null,
    completed_response_count: 0,
  };
}
