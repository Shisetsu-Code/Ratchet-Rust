import { useEffect, useRef, useState } from 'react';
import { claimCustomerAccess } from '../leads/api';
import { openLocalDatabase } from '../storage/db';
import { friendlyError } from '../ui/errors';
import '../ui/styles.css';

export function AccessApp(props: { token: string }) {
  const deviceName = navigator.platform || 'Navegador';
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  const activate = async () => {
    setBusy(true);
    setError(null);
    const db = await openLocalDatabase().catch((cause) => {
      setError(friendlyError(cause));
      return null;
    });
    if (!db) { setBusy(false); return; }
    try {
      await claimCustomerAccess(db, props.token, deviceName.trim() || 'Navegador');
      window.history.replaceState({}, '', window.location.pathname);
      window.location.replace('/');
    } catch (cause) {
      setError(friendlyError(cause));
      setBusy(false);
    } finally {
      db.close();
    }
  };

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void activate();
  }, []);

  return (
    <div className="auth-page">
      <section className="auth-card">
        <div className="brand auth-brand"><span className="brand-mark">R</span><div><h1>Ratchet</h1><small>Soporte seguro</small></div></div>
        <h2>{error ? 'No se pudo entrar' : 'Abriendo tu chat…'}</h2>
        <p>{error ? 'El enlace puede haber vencido o ya fue usado.' : 'Estamos conectando este dispositivo de forma segura.'}</p>
        {error && <button onClick={() => { started.current = false; void activate(); }} disabled={busy}>{busy ? 'Conectando…' : 'Intentar de nuevo'}</button>}
        <p className="notice">No necesitás usuario, contraseña, llave de seguridad ni Windows Hello.</p>
        {error && <p className="error-text" role="alert">{error}</p>}
      </section>
    </div>
  );
}
