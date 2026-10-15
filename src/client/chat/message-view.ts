export type MessageViewMutation = {
  target_message_id: string;
  type: 'EDIT' | 'TOMBSTONE';
};

export type MaterializableMessage<TAttachment = unknown> = {
  message_id: string | null;
  client_message_id: string;
  mutation: MessageViewMutation | null;
  reply_to_message_id: string | null;
  text: string;
  attachments: TAttachment[];
  edited?: boolean;
  deleted?: boolean;
};

/**
 * Materialize mutation records into the visible chat timeline.
 *
 * Mutation records are transport/history facts, not visible messages. EDIT
 * replaces the target's visible content. TOMBSTONE removes the target entirely
 * and suppresses reply previews that would otherwise leave a visible trace of
 * the deleted message.
 */
export function materializeMessageMutations<T extends MaterializableMessage>(ordered: readonly T[]): T[] {
  const mutations = ordered.filter((message) => message.mutation !== null);
  const mutationIds = new Set(mutations.map((message) => message.client_message_id));
  let visible = ordered.filter((message) => !mutationIds.has(message.client_message_id));
  const deletedMessageIds = new Set<string>();

  for (const mutationMessage of mutations) {
    const mutation = mutationMessage.mutation!;
    if (mutation.type === 'TOMBSTONE') {
      deletedMessageIds.add(mutation.target_message_id);
      visible = visible.filter((message) => message.message_id !== mutation.target_message_id);
      continue;
    }

    const targetIndex = visible.findIndex((message) => message.message_id === mutation.target_message_id);
    if (targetIndex < 0) continue;
    const target = visible[targetIndex]!;
    visible[targetIndex] = {
      ...target,
      text: mutationMessage.text,
      attachments: mutationMessage.attachments,
      edited: true,
      deleted: false,
    };
  }

  if (deletedMessageIds.size > 0) {
    visible = visible.map((message) => message.reply_to_message_id && deletedMessageIds.has(message.reply_to_message_id)
      ? { ...message, reply_to_message_id: null }
      : message);
  }

  return visible;
}
