import { useCallback, useEffect, useRef, useState } from 'react';
import { claimLeadAccess } from '../leads/api';
import { openLocalDatabase } from '../storage/db';
import { friendlyError } from '../ui/errors';
import '../ui/styles.css';

export function LeadAccessApp(props: { token: string }) {
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const attempted = useRef(false);

  const enter = useCallback(async () => {
    setBusy(true);
    setError(null);
    const db = await openLocalDatabase().catch((cause) => {
      setError(friendlyError(cause));
      return null;
    });
    if (!db) { setBusy(false); return; }
    try {
      const result = await claimLeadAccess(db, props.token, navigator.platform || 'Navegador del invitado');
      window.location.replace(`/?chat=${encodeURIComponent(result.chat_id)}`);
    } catch (cause) {
      setError(friendlyError(cause));
      setBusy(false);
    } finally {
      db.close();
    }
  }, [props.token]);

  useEffect(() => {
    if (attempted.current) return;
    attempted.current = true;
    void enter();
  }, [enter]);

  return <div className="auth-page">
    <section className="auth-card">
      <div className="brand auth-brand"><span className="brand-mark">R</span><div><h1>Ratchet</h1><small>Soporte seguro</small></div></div>
      <h2>{error ? 'No pudimos abrir el chat' : 'Conectando…'}</h2>
      {error
        ? <><p className="error-text" role="alert">{error}</p><button onClick={() => void enter()} disabled={busy}>{busy ? 'Reintentando…' : 'Reintentar'}</button></>
        : <div className="loading-indicator" role="status" aria-label="Abriendo el chat" />}
    </section>
  </div>;
}
