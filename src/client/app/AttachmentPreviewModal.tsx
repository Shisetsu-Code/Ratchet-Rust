import { useEffect, useState } from 'react';
import type { AttachmentDescriptor } from '../attachments/crypto';
import { downloadLoadedAttachment, loadDecryptedAttachment, loadLocalAttachment, type LoadedAttachment } from '../attachments/message';

export type AttachmentPreviewSource =
  | { kind: 'remote'; chatId: string; descriptor: AttachmentDescriptor }
  | { kind: 'local'; file: File };

export function AttachmentPreviewModal({ source, onClose }: { source: AttachmentPreviewSource; onClose: () => void }) {
  const [attachment, setAttachment] = useState<LoadedAttachment | null>(null);
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const abort = new AbortController();
    let url: string | null = null;
    setAttachment(null);
    setObjectUrl(null);
    setError(null);
    const load = source.kind === 'local'
      ? loadLocalAttachment(source.file)
      : loadDecryptedAttachment(source.chatId, source.descriptor, abort.signal);
    void load.then((loaded) => {
      if (abort.signal.aborted) return;
      url = URL.createObjectURL(loaded.blob);
      setAttachment(loaded);
      setObjectUrl(url);
    }).catch((cause: unknown) => {
      if (!abort.signal.aborted) setError(cause instanceof Error ? cause.message : 'No se pudo abrir el archivo.');
    });
    return () => {
      abort.abort();
      if (url) URL.revokeObjectURL(url);
    };
  }, [source]);

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [onClose]);

  return <div className="modal-backdrop attachment-preview-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="attachment-preview" role="dialog" aria-modal="true" aria-label="Vista previa del archivo">
      <header className="attachment-preview-header">
        <div><h2>{attachment?.name || 'Abriendo archivo…'}</h2>{attachment && <p>{formatBytes(attachment.size)} · {attachment.type === 'application/pdf' ? 'PDF' : 'Imagen'}</p>}</div>
        <button className="icon-button" onClick={onClose} aria-label="Cerrar vista previa">×</button>
      </header>
      <div className="attachment-preview-content">
        {!objectUrl && !error && <p role="status">Descifrando y verificando el archivo…</p>}
        {error && <div className="attachment-preview-error" role="alert"><strong>No se puede mostrar este archivo.</strong><p>{error}</p></div>}
        {objectUrl && !error && attachment?.type.startsWith('image/') && <img src={objectUrl} alt={attachment.name} onError={() => setError('El navegador no pudo decodificar la imagen. El archivo puede estar dañado.')} />}
        {objectUrl && attachment?.type === 'application/pdf' && <iframe src={objectUrl} title={attachment.name} sandbox="" referrerPolicy="no-referrer" />}
      </div>
      <footer className="attachment-preview-actions">
        {attachment && <button onClick={() => downloadLoadedAttachment(attachment)}>Descargar</button>}
        <button className="secondary" onClick={onClose}>Cerrar</button>
      </footer>
    </section>
  </div>;
}

function formatBytes(bytes: number): string {
  return bytes < 1024 * 1024 ? `${Math.ceil(bytes / 1024)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
