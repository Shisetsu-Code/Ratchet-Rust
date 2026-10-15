import { memo, useEffect, useState } from 'react';
import type { UiMessage } from './SecureApp';
import type { AttachmentDescriptor } from '../attachments/crypto';
import { loadDecryptedAttachment, loadLocalAttachment } from '../attachments/message';
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
  const [preview, setPreview] = useState<{ url: string; name: string; type: string } | null>(null);
  useEffect(() => {
    const abort = new AbortController();
    let objectUrl: string | null = null;
    const loading = props.localFile ? loadLocalAttachment(props.localFile) : loadDecryptedAttachment(props.chatId, props.descriptor, abort.signal);
    void loading.then((file) => {
      if (abort.signal.aborted) return;
      objectUrl = URL.createObjectURL(file.blob);
      setPreview({ url: objectUrl, name: file.name, type: file.type });
    }).catch(() => undefined);
    return () => { abort.abort(); if (objectUrl) URL.revokeObjectURL(objectUrl); };
  }, [props.chatId, props.descriptor.file_id, props.localFile]);
  return <button className="attachment-inline-preview" aria-label={`Ver adjunto ${shortId(props.descriptor.file_id)}`} onClick={props.onOpen}>
    {preview?.type.startsWith('image/') ? <img src={preview.url} alt={preview.name} /> : <span className="pdf-preview-icon">PDF</span>}
    <span>{preview?.name ?? 'Abriendo adjunto…'}</span>
  </button>;
}
