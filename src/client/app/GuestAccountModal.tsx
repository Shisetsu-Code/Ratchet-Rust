import { useState } from 'react';
import { createCustomerAccess, createGuestAccount, setCustomerPassword } from '../leads/api';
import { friendlyError } from '../ui/errors';

type CreatedAccount = { loginName: string; accessUrl: string; expiresAt: string };

export function GuestAccountModal(props: { chatId: string; accountExists: boolean; canManagePassword: boolean; onCreated: () => Promise<void>; onClose: () => void }) {
  const [loginName, setLoginName] = useState('');
  const [customerName, setCustomerName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedAccount | null>(null);
  const [copied, setCopied] = useState(false);
  const [passwordSaved, setPasswordSaved] = useState(false);

  const submit = async () => {
    if (!props.accountExists && !customerName.trim()) { setError('Escribí el nombre o apodo con el que querés identificar al cliente.'); return; }
    setBusy(true); setError(null);
    try {
      const result = props.accountExists
        ? await createCustomerAccess(props.chatId)
        : await createGuestAccount(props.chatId, { display_name: customerName.trim() });
      const url = new URL('/', window.location.origin);
      url.hash = new URLSearchParams({ access: result.token }).toString();
      setCreated({ loginName: result.login_name ?? '', accessUrl: url.toString(), expiresAt: result.expires_at });
      setPassword(''); setConfirmation('');
      await props.onCreated();
      if (!props.accountExists) window.setTimeout(props.onClose, 900);
    } catch (cause) { setError(friendlyError(cause)); }
    finally { setBusy(false); }
  };

  const savePassword = async () => {
    if (!/^[A-Za-z0-9._-]{3,64}$/.test(loginName.trim())) { setError('Ingresá un usuario válido.'); return; }
    if (password.length < 15 || password !== confirmation) { setError('La contraseña debe tener al menos 15 caracteres y coincidir.'); return; }
    setBusy(true); setError(null);
    try { await setCustomerPassword(props.chatId, loginName.trim(), password); setPassword(''); setConfirmation(''); setPasswordSaved(true); }
    catch (cause) { setError(friendlyError(cause)); } finally { setBusy(false); }
  };

  const copy = async () => {
    if (!created) return;
    try { await navigator.clipboard.writeText(created.accessUrl); setCopied(true); }
    catch (cause) { setError(friendlyError(cause)); }
  };

  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) props.onClose(); }}>
    <section className="security-panel guest-account-panel" role="dialog" aria-modal="true" aria-label={props.accountExists ? 'Dar acceso al cliente' : 'Crear cuenta para el invitado'}>
      <header className="panel-header"><div><h2>{props.accountExists ? 'Dar acceso en otro dispositivo' : 'Convertir invitado en cliente'}</h2><p>El cliente y todo el historial continúan en este mismo chat compartido.</p></div><button className="icon-button" onClick={props.onClose} aria-label="Cerrar">×</button></header>
      <div className="account-panel-content">
        {error && <div className="error-banner">{error}<button onClick={() => setError(null)}>×</button></div>}
        {!created ? <section className="security-section">
          <p>{props.accountExists ? 'Generá un enlace de un solo uso. Vence en 24 horas.' : 'La cuenta funciona automáticamente en este dispositivo. La contraseña es opcional.'}</p>
          {!props.accountExists && <label>Nombre o apodo del cliente<input autoFocus value={customerName} maxLength={80} placeholder="Ejemplo: María López" onChange={(event) => setCustomerName(event.target.value)} /></label>}
          {props.canManagePassword && props.accountExists && <details><summary>Agregar o cambiar contraseña (opcional)</summary>
            <label>Usuario<input value={loginName} autoComplete="off" minLength={3} maxLength={64} onChange={(event) => setLoginName(event.target.value)} /></label>
            <label>{props.accountExists ? 'Nueva contraseña' : 'Contraseña inicial'}<input type="password" value={password} autoComplete="new-password" minLength={15} maxLength={256} onChange={(event) => setPassword(event.target.value)} /></label>
            <label>Confirmar contraseña<input type="password" value={confirmation} autoComplete="new-password" minLength={15} maxLength={256} onChange={(event) => setConfirmation(event.target.value)} /></label>
            <button className="secondary" onClick={() => void savePassword()} disabled={busy}>{passwordSaved ? 'Contraseña guardada' : 'Guardar contraseña'}</button>
          </details>}
          <button onClick={() => void submit()} disabled={busy}>{busy ? 'Preparando…' : props.accountExists ? 'Generar enlace de acceso' : 'Crear cuenta y conservar chat'}</button>
        </section> : <section className="security-section"><div className="reauth-card">
          <strong>{props.accountExists ? 'Enlace de acceso listo' : 'Cuenta creada sin mover la conversación'}</strong>
          {props.accountExists ? <>{created.loginName && <p>Usuario opcional: <code>{created.loginName}</code></p>}<code>{created.accessUrl}</code>
            <p>Vence: {new Date(created.expiresAt).toLocaleString()}. Es de un solo uso.</p>
            <button onClick={() => void copy()}>{copied ? 'Enlace copiado' : 'Copiar enlace'}</button></> : <p>El cliente ya quedó identificado y continúa automáticamente en este mismo chat.</p>}
        </div></section>}
      </div>
    </section>
  </div>;
}
