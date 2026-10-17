import { memo } from 'react';
import type { UiMessage } from './SecureApp';
import type { AttachmentDescriptor } from '../attachments/crypto';
import type { AttachmentPreviewSource } from './AttachmentPreviewModal';
import { formatMessageTime } from '../ui/message-time';

export const MessageBubble = memo(function MessageBubble({message,replied,senderLabel,isCustomer,localFiles,onReply,onMutate,onPreview}: {
  message: UiMessage;
  replied: UiMessage | null | undefined;
  senderLabel: string;
  isCustomer: boolean;
  localFiles: Map<string, File>;
  onReply: (message: UiMessage) => void;
  onMutate: (message: UiMessage, type: 'EDIT' | 'TOMBSTONE') => void;
  onPreview: (source: AttachmentPreviewSource) => void;
}) {
  return <article className={message.direction === 'OUTGOING' ? 'bubble own' : 'bubble'}>
              {message.reply_to_message_id && <div className="reply-preview"><strong>Respuesta</strong><span>{replied?.text || (replied?.attachments.length ? 'Adjunto' : 'Mensaje anterior')}</span></div>}
              {message.text && <p>{message.text}</p>}
              {message.attachments.length > 0 && <div className="message-attachments">{message.attachments.map((attachment) => <InlineAttachmentPreview key={attachment.file_id} chatId={message.chat_id} descriptor={attachment} localFile={localFiles.get(attachment.file_id)} onOpen={() => { const localFile = localFiles.get(attachment.file_id); onPreview(localFile ? { kind: 'local', file: localFile } : { kind: 'remote', chatId: message.chat_id, descriptor: attachment }); }} />)}</div>}
              <footer>{senderLabel} · {formatMessageTime(message.created_at)}{!isCustomer && message.edited ? ' · editado' : ''}{message.delivery_state === 'PENDING' ? ' · pendiente' : message.delivery_state === 'RETRYING' ? ' · enviando' : message.delivery_state === 'FAILED' ? ' · no enviado' : message.direction === 'OUTGOING' && message.receipt_state === 'READ' ? ' · ✓✓ visto' : message.direction === 'OUTGOING' && message.receipt_state === 'DELIVERED' ? ' · ✓✓ entregado' : message.direction === 'OUTGOING' && message.message_id ? ' · ✓ enviado' : ''}{message.message_id && !message.deleted && <span className="message-actions"><button onClick={() => onReply(message)}>Responder</button>{!isCustomer && <><button onClick={() => onMutate(message, 'EDIT')}>Editar</button><button onClick={() => onMutate(message, 'TOMBSTONE')}>Borrar</button></>}</span>}</footer>
            </article>;
});

function shortId(value: string): string { return value.slice(0, 8); }
function InlineAttachmentPreview(props: { chatId: string; descriptor: AttachmentDescriptor; localFile?: File | undefined; onOpen: () => void }) {
  // Descriptors intentionally do not expose the remote filename/type. Opening
  // the explicit preview decrypts them; mounting history never downloads files.
  return <button className="attachment-inline-preview" aria-label={`Ver adjunto ${shortId(props.descriptor.file_id)}`} onClick={props.onOpen}>
    <span className="pdf-preview-icon" aria-hidden="true">↧</span>
    <span>{props.localFile?.name ?? 'Ver adjunto'} · {(props.descriptor.plaintext_size / (1024 * 1024)).toFixed(1)} MB</span>
  </button>;
}
