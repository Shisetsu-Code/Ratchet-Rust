import { useCallback, useEffect, useRef, useState } from 'react';
import { claimOperatorAccess } from '../operators/access';
import { openLocalDatabase } from '../storage/db';
import { friendlyError } from '../ui/errors';
import '../ui/styles.css';

export function AgentAccessApp(props: { token: string }) {
  const started = useRef(false);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const enter = useCallback(async () => {
    setBusy(true);
    setError(null);
    const db = await openLocalDatabase().catch((cause) => {
      setError(friendlyError(cause));
      return null;
    });
    if (!db) { setBusy(false); return; }
    try {
      await claimOperatorAccess(db, props.token, navigator.platform || 'Navegador');
      window.location.replace('/');
    } catch (cause) {
      setError(friendlyError(cause));
      setBusy(false);
    } finally {
      db.close();
    }
  }, [props.token]);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void enter();
  }, [enter]);

  return (
    <div className="auth-page">
      <section className="auth-card">
        <div className="brand auth-brand"><span className="brand-mark">R</span><div><h1>Ratchet</h1><small>Soporte seguro</small></div></div>
        <h2>Acceso de agente</h2>
        {busy ? <p>Validando acceso y vinculando este dispositivo…</p> : <p>El enlace no pudo usarse.</p>}
        {error && <p className="error-text" role="alert">{error}</p>}
        {!busy && <button onClick={() => void enter()}>Reintentar</button>}
      </section>
    </div>
  );
}
