import type { IDBPDatabase } from 'idb';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { CurrentSessionResponse } from '../../shared/contracts/session';
import type { OperatorRecord } from '../../shared/contracts/operators';
import {
  completeReauthentication,
  passwordReauthenticate,
  portableKeyReauthenticate,
  prepareReauthentication,
  type PreparedReauthentication,
  updateStaffDisplayName,
} from '../auth/api';
import {
  CHAT_WALLPAPER_PRESETS,
  type ChatWallpaper,
  type ChatWallpaperPreset,
} from '../appearance/wallpaper';
import {
  deviceIdentityFingerprint,
  listOwnDevices,
  revokeDeviceHttp,
  type OwnDevice,
} from '../devices/api';
import { createInvitation } from '../invitations/api';
import {
  createOperator,
  createOperatorAccessGrant,
  listOperators,
  revokeOperator,
} from '../operators/api';
import type { LocalDbSchema } from '../storage/schema';
import { friendlyError } from '../ui/errors';

export type SecurityAction = { kind: 'revoke'; device: OwnDevice };

export type AccountPanelSection = 'clients' | 'agents' | 'appearance' | 'devices';

type GeneratedInvitation = {
  kind: 'ACCESS' | 'REFERRAL';
  url: string;
  expiresAt: string | null;
  loginName: string | null;
};

type GeneratedAgentAccess = {
  operatorUserId: string;
  operatorName: string;
  grantId: string;
  url: string;
  expiresAt: string;
};

export function AccountSecurityPanel(props: {
  db: IDBPDatabase<LocalDbSchema>;
  session: CurrentSessionResponse;
  selectedChatId: string | null;
  chatWallpaper: ChatWallpaper;
  canManageChatWallpaper: boolean;
  initialSection: AccountPanelSection;
  onChatWallpaperChange: (wallpaper: ChatWallpaper) => Promise<void>;
  onCustomWallpaperFile: (file: File) => Promise<void>;
  onSessionChange: (session: CurrentSessionResponse) => void;
  onClose: () => void;
  onCurrentDeviceRevoked: () => void;
}) {
  const [devices, setDevices] = useState<OwnDevice[]>([]);
  const [busy, setBusy] = useState(false);
  const wallpaperInput = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<SecurityAction | null>(null);
  const [reauth, setReauth] = useState<PreparedReauthentication | null>(null);
  const [reauthFile, setReauthFile] = useState<File | null>(null);
  const [reauthPassword, setReauthPassword] = useState('');
  const [accountPassword, setAccountPassword] = useState('');
  const referralWorkspaceIds = props.session.staff_memberships
    .filter((membership) => membership.staff_role === 'ADMIN' || membership.staff_role === 'OPERATOR')
    .map((membership) => membership.workspace_id);
  const [inviteWorkspaceId, setInviteWorkspaceId] = useState(referralWorkspaceIds[0] ?? props.session.workspace_ids[0] ?? '');
  const [customerLoginName, setCustomerLoginName] = useState('');
  const [customerPassword, setCustomerPassword] = useState('');
  const [generatedInvitation, setGeneratedInvitation] = useState<GeneratedInvitation | null>(null);
  const [copied, setCopied] = useState(false);
  const [operators, setOperators] = useState<OperatorRecord[]>([]);
  const [canManageOperators, setCanManageOperators] = useState(false);
  const [operatorDisplayName, setOperatorDisplayName] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [generatedAgentAccess, setGeneratedAgentAccess] = useState<GeneratedAgentAccess | null>(null);
  const [agentCopied, setAgentCopied] = useState(false);
  const [activeSection, setActiveSection] = useState<AccountPanelSection>(props.initialSection);
  const visibleMemberships = props.session.staff_memberships.filter((membership) => membership.staff_role === 'ADMIN' || membership.staff_role === 'OPERATOR');
  const [nicknameWorkspaceId, setNicknameWorkspaceId] = useState(visibleMemberships[0]?.workspace_id ?? '');
  const currentVisibleMembership = visibleMemberships.find((membership) => membership.workspace_id === nicknameWorkspaceId);
  const [nickname, setNickname] = useState(currentVisibleMembership?.display_name ?? '');

  const currentStaffRole = props.session.staff_memberships
    .find((membership) => membership.workspace_id === inviteWorkspaceId)?.staff_role ?? null;
  const isExactWorkspaceAdmin = currentStaffRole === 'ADMIN';
  const canIssueReferral = currentStaffRole === 'ADMIN' || currentStaffRole === 'OPERATOR';
  const sections: Array<{ id: AccountPanelSection; label: string }> = [
    ...(canIssueReferral ? [{ id: 'clients' as const, label: 'Invitaciones al chat' }] : []),
    ...(isExactWorkspaceAdmin ? [{ id: 'agents' as const, label: 'Agentes' }] : []),
    { id: 'appearance', label: 'Apariencia' },
    { id: 'devices', label: 'Dispositivos' },
  ];

  const refresh = useCallback(async () => {
    setDevices(await listOwnDevices());
    if (isExactWorkspaceAdmin && inviteWorkspaceId) {
      const team = await listOperators(inviteWorkspaceId);
      setOperators(team.operators);
      setCanManageOperators(team.can_manage);
    } else {
      setOperators([]);
      setCanManageOperators(false);
    }
  }, [isExactWorkspaceAdmin, inviteWorkspaceId]);

  useEffect(() => {
    void refresh().catch((cause) => setError(describe(cause)));
  }, [refresh]);

  useEffect(() => {
    setGeneratedAgentAccess(null);
    setAgentCopied(false);
  }, [inviteWorkspaceId]);

  const prepareAction = async (action: SecurityAction) => {
    setError(null);
    setPendingAction(action);
    setReauth(null);
  };

  const preparePasskeyAction = async () => {
    setBusy(true); setError(null);
    try { setReauth(await prepareReauthentication()); }
    catch (cause) { setError(describe(cause)); }
    finally { setBusy(false); }
  };

  const completeAction = async () => {
    if (!reauth || !pendingAction) return;
    setBusy(true);
    setError(null);
    try {
      await completeReauthentication(reauth);
      if (pendingAction.kind === 'revoke') {
        await revokeDeviceHttp(pendingAction.device.device_id);
        if (pendingAction.device.device_id === props.session.device_id) {
          setPendingAction(null);
          setReauth(null);
          props.onCurrentDeviceRevoked();
          return;
        }
      }
      setPendingAction(null);
      setReauth(null);
      await refresh();
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(false);
    }
  };

  const completePortableAction = async () => {
    if (!reauthFile || !pendingAction || reauthPassword.length < 15) return;
    setBusy(true); setError(null);
    try {
      await portableKeyReauthenticate(reauthFile, reauthPassword);
      if (pendingAction.kind === 'revoke') {
        await revokeDeviceHttp(pendingAction.device.device_id);
        if (pendingAction.device.device_id === props.session.device_id) { props.onCurrentDeviceRevoked(); return; }
      }
      setPendingAction(null); setReauth(null); setReauthFile(null); setReauthPassword('');
      await refresh();
    } catch (cause) { setError(describe(cause)); }
    finally { setBusy(false); }
  };

  const completePasswordAction = async () => {
    if (!pendingAction || accountPassword.length < 15) return;
    setBusy(true); setError(null);
    try {
      await passwordReauthenticate(accountPassword);
      if (pendingAction.kind === 'revoke') {
        await revokeDeviceHttp(pendingAction.device.device_id);
        if (pendingAction.device.device_id === props.session.device_id) { props.onCurrentDeviceRevoked(); return; }
      }
      setPendingAction(null); setAccountPassword('');
      await refresh();
    } catch (cause) { setError(describe(cause)); }
    finally { setBusy(false); }
  };

  const generateInvitation = async (kind: 'ACCESS' | 'REFERRAL') => {
    if (!inviteWorkspaceId || (kind === 'ACCESS' ? !isExactWorkspaceAdmin : !canIssueReferral)) return;
    if (kind === 'ACCESS') {
      if (!/^[A-Za-z0-9._-]{3,64}$/.test(customerLoginName.trim())) {
        setError('El usuario debe tener entre 3 y 64 caracteres: letras, números, punto, guion o guion bajo.');
        return;
      }
      if (customerPassword.length < 15) {
        setError('La contraseña inicial debe tener al menos 15 caracteres.');
        return;
      }
    }
    setBusy(true);
    setError(null);
    setCopied(false);
    try {
      const created = kind === 'ACCESS'
        ? await createInvitation({
          kind,
          workspace_id: inviteWorkspaceId,
          login_name: customerLoginName.trim(),
          password: customerPassword,
        })
        : await createInvitation({ kind, workspace_id: inviteWorkspaceId });
      if (kind === 'ACCESS' && !created.expires_at) throw new Error('El servidor no devolvió vencimiento para el acceso');
      const url = new URL('/', window.location.origin);
      url.hash = new URLSearchParams({ [kind === 'ACCESS' ? 'access' : 'lead']: created.token }).toString();
      setGeneratedInvitation({
        kind,
        url: url.toString(),
        expiresAt: created.expires_at,
        loginName: created.login_name,
      });
      if (kind === 'ACCESS') {
        setCustomerPassword('');
        setCustomerLoginName('');
      }
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(false);
    }
  };

  const rememberAgentGrant = (operator: Pick<OperatorRecord, 'user_id' | 'display_name'>, grant: { grant_id: string; token: string; expires_at: string }) => {
    const url = new URL('/', window.location.origin);
    url.hash = new URLSearchParams({ agent: grant.token }).toString();
    setGeneratedAgentAccess({
      operatorUserId: operator.user_id,
      operatorName: operator.display_name,
      grantId: grant.grant_id,
      url: url.toString(),
      expiresAt: grant.expires_at,
    });
    setAgentCopied(false);
  };

  const createTeamOperator = async () => {
    if (!inviteWorkspaceId || !canManageOperators || !isExactWorkspaceAdmin) return;
    if (!operatorDisplayName.trim()) { setError('Ingresá el nombre visible del agente.'); return; }
    if (adminPassword.length < 15) { setError('Ingresá la contraseña del administrador.'); return; }
    setBusy(true); setError(null);
    try {
      await passwordReauthenticate(adminPassword);
      const operator = await createOperator({
        workspace_id: inviteWorkspaceId,
        display_name: operatorDisplayName.trim(),
      });
      const grant = await createOperatorAccessGrant(inviteWorkspaceId, operator.user_id);
      rememberAgentGrant(operator, grant);
      setOperatorDisplayName('');
      setAdminPassword('');
      await refresh();
    } catch (cause) { setError(describe(cause)); }
    finally { setBusy(false); }
  };

  const generateAgentAccess = async (operator: OperatorRecord) => {
    if (!canManageOperators || !isExactWorkspaceAdmin || operator.staff_role !== 'OPERATOR' || operator.revoked_at) return;
    if (adminPassword.length < 15) { setError('Ingresá la contraseña del administrador para generar el acceso.'); return; }
    setBusy(true); setError(null);
    try {
      await passwordReauthenticate(adminPassword);
      const grant = await createOperatorAccessGrant(inviteWorkspaceId, operator.user_id);
      rememberAgentGrant(operator, grant);
      setAdminPassword('');
      await refresh();
    } catch (cause) { setError(describe(cause)); }
    finally { setBusy(false); }
  };

  const revokeTeamOperator = async (operator: OperatorRecord) => {
    if (!canManageOperators || !isExactWorkspaceAdmin || adminPassword.length < 15) {
      setError('Ingresá la contraseña del administrador para desconectar al agente.');
      return;
    }
    setBusy(true); setError(null);
    try {
      await passwordReauthenticate(adminPassword);
      await revokeOperator(inviteWorkspaceId, operator.user_id);
      setAdminPassword('');
      if (generatedAgentAccess?.operatorUserId === operator.user_id) setGeneratedAgentAccess(null);
      await refresh();
    } catch (cause) { setError(describe(cause)); }
    finally { setBusy(false); }
  };

  const copyInvitation = async () => {
    if (!generatedInvitation) return;
    try {
      await navigator.clipboard.writeText(generatedInvitation.url);
      setCopied(true);
    } catch (cause) { setError(describe(cause)); }
  };

  const copyAgentAccess = async () => {
    if (!generatedAgentAccess) return;
    try {
      await navigator.clipboard.writeText(generatedAgentAccess.url);
      setAgentCopied(true);
    } catch (cause) { setError(describe(cause)); }
  };

  const chooseWallpaperPreset = async (preset: ChatWallpaperPreset) => {
    setBusy(true); setError(null);
    try { await props.onChatWallpaperChange({ kind: 'preset', preset }); }
    catch (cause) { setError(describe(cause)); }
    finally { setBusy(false); }
  };

  const chooseWallpaperFile = async (file: File | null) => {
    if (!file || !props.selectedChatId || !props.canManageChatWallpaper) return;
    setBusy(true); setError(null);
    try {
      await props.onCustomWallpaperFile(file);
    } catch (cause) {
      setError(describe(cause));
    } finally {
      setBusy(false);
    }
  };

  const saveNickname = async () => {
    if (!nicknameWorkspaceId || !nickname.trim()) return;
    setBusy(true); setError(null);
    try {
      const updated = await updateStaffDisplayName(nicknameWorkspaceId, nickname.trim());
      props.onSessionChange({ ...props.session, staff_memberships: props.session.staff_memberships.map((membership) =>
        membership.workspace_id === updated.workspace_id ? { ...membership, display_name: updated.display_name } : membership) });
      setNickname(updated.display_name);
    } catch (cause) { setError(describe(cause)); } finally { setBusy(false); }
  };

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) props.onClose();
    }}>
      <section className="security-panel" role="dialog" aria-modal="true" aria-label="Seguridad y administración de la cuenta">
        <header className="panel-header">
          <div><h2>Administración y opciones</h2><p>Elegí una sección. El chat queda intacto detrás de esta ventana.</p></div>
          <button className="icon-button" onClick={props.onClose} aria-label="Cerrar">×</button>
        </header>
        <div className="account-panel-layout">
          <label className="account-section-picker">Sección
            <select aria-label="Sección" value={activeSection} onChange={(event) => { setActiveSection(event.target.value as AccountPanelSection); setError(null); }}>
              {sections.map(section => <option key={section.id} value={section.id}>{section.label}</option>)}
            </select>
          </label>
          <nav className="account-panel-tabs" aria-label="Secciones de administración">
            {sections.map((section) => <button key={section.id} className={activeSection === section.id ? 'active' : ''} aria-current={activeSection === section.id ? 'page' : undefined} onClick={() => { setActiveSection(section.id); setError(null); }}>{section.label}</button>)}
          </nav>
          <div className="account-panel-content">
        {error && <div className="error-banner">{error}<button onClick={() => setError(null)}>×</button></div>}

        {pendingAction && (
          <div className="reauth-card">
            <strong>Confirmá con tu contraseña</strong>
            <p>Vas a desconectar un navegador de esta cuenta.</p>
            <label>Contraseña de la cuenta<input type="password" autoComplete="current-password" value={accountPassword} onChange={(event) => setAccountPassword(event.target.value)} /></label>
            <button onClick={() => void completePasswordAction()} disabled={busy || accountPassword.length < 15}>Confirmar</button>
            <details><summary>Otras formas de confirmar</summary>
              <label>Archivo .ratchet-key<input type="file" accept=".ratchet-key,application/json" onChange={(event) => setReauthFile(event.currentTarget.files?.[0] ?? null)} /></label>
              <label>Contraseña del archivo<input type="password" autoComplete="current-password" value={reauthPassword} onChange={(event) => setReauthPassword(event.target.value)} /></label>
              <button onClick={() => void completePortableAction()} disabled={busy || !reauthFile || reauthPassword.length < 15}>Confirmar con archivo</button>
              {!reauth
                ? <button className="secondary" onClick={() => void preparePasskeyAction()} disabled={busy}>Usar passkey</button>
                : <button className="secondary" onClick={() => void completeAction()} disabled={busy}>Confirmar con passkey</button>}
            </details>
            <button className="secondary" onClick={() => { setPendingAction(null); setReauth(null); setReauthFile(null); setReauthPassword(''); setAccountPassword(''); }} disabled={busy}>Cancelar</button>
          </div>
        )}

        {activeSection === 'agents' && isExactWorkspaceAdmin && props.session.workspace_ids.length > 0 && (
          <section className="security-section">
            <div className="section-heading">
              <div><h3>Tu cuenta y tus agentes</h3><p>Sólo aparecen tu cuenta de administrador y los agentes creados por vos. Cada link de acceso vincula exactamente un dispositivo y vence a las 8 horas.</p></div>
              <button className="secondary" onClick={() => void refresh()} disabled={busy}>Actualizar</button>
            </div>
            {props.session.workspace_ids.length > 1 && (
              <label>Workspace<select value={inviteWorkspaceId} onChange={(event) => setInviteWorkspaceId(event.target.value)}>{props.session.workspace_ids.map((id) => <option key={id} value={id}>{shortId(id)}</option>)}</select></label>
            )}
            <div className="device-list">
              {operators.map((operator) => (
                <article className="device-card" key={operator.user_id}>
                  <div className="device-card-main">
                    <strong>{operator.display_name} · {staffRoleLabel(operator.staff_role)}</strong>
                    <span>{operator.revoked_at
                      ? 'Desconectado'
                      : `${operator.active_device_count} dispositivo(s) activo(s) · ${operator.pending_access_grant_count} acceso(s) de 8 h pendiente(s)`}</span>
                    {operator.last_seen_at && <span>Última actividad: {new Date(operator.last_seen_at).toLocaleString()}</span>}
                  </div>
                  {canManageOperators && operator.staff_role === 'OPERATOR' && !operator.revoked_at && (
                    <div className="device-actions">
                      <button className="secondary" onClick={() => void generateAgentAccess(operator)} disabled={busy || adminPassword.length < 15}>Generar acceso 8 h</button>
                      <button className="danger-secondary" onClick={() => void revokeTeamOperator(operator)} disabled={busy || adminPassword.length < 15}>Desconectar agente</button>
                    </div>
                  )}
                </article>
              ))}
            </div>

            {generatedAgentAccess && (
              <div className="reauth-card">
                <strong>Acceso de agente generado · {generatedAgentAccess.operatorName}</strong>
                <code>{generatedAgentAccess.url}</code>
                <p>Vence: {new Date(generatedAgentAccess.expiresAt).toLocaleString()}. Es de un solo uso; al abrirlo queda ligado a ese dispositivo y no puede reutilizarse.</p>
                <button className="secondary" onClick={() => void copyAgentAccess()}>{agentCopied ? 'Copiado' : 'Copiar enlace'}</button>
              </div>
            )}

            {canManageOperators && isExactWorkspaceAdmin ? (
              <div className="reauth-card">
                <strong>Administrar agentes</strong>
                <label>Nombre visible del nuevo agente<input value={operatorDisplayName} maxLength={80} onChange={(event) => setOperatorDisplayName(event.target.value)} /></label>
                <label>Contraseña del administrador<input type="password" value={adminPassword} autoComplete="current-password" minLength={15} maxLength={256} onChange={(event) => setAdminPassword(event.target.value)} /></label>
                <p>El agente no recibe usuario ni contraseña. “Crear agente y enlace” genera un acceso de un solo uso válido por 8 horas. Para otro dispositivo, generá otro enlace.</p>
                <button onClick={() => void createTeamOperator()} disabled={busy || !operatorDisplayName.trim() || adminPassword.length < 15}>Crear agente y enlace</button>
              </div>
            ) : <p className="notice">Sólo un administrador del workspace puede crear agentes o emitir enlaces de acceso.</p>}
          </section>
        )}

        {activeSection === 'appearance' && <section className="security-section">
          {visibleMemberships.length > 0 && <div className="reauth-card">
            <h3>Apodo visible en el chat</h3>
            <p>Es sólo el nombre que ven los clientes. Puede repetirse y no cambia tu usuario, identidad, permisos ni forma de ingresar.</p>
            {visibleMemberships.length > 1 && <label>Equipo<select value={nicknameWorkspaceId} onChange={(event) => { const workspaceId = event.target.value; setNicknameWorkspaceId(workspaceId); setNickname(visibleMemberships.find((membership) => membership.workspace_id === workspaceId)?.display_name ?? ''); }}>{visibleMemberships.map((membership) => <option key={membership.workspace_id} value={membership.workspace_id}>{shortId(membership.workspace_id)}</option>)}</select></label>}
            <label>Tu apodo<input value={nickname} maxLength={80} onChange={(event) => setNickname(event.target.value)} /></label>
            <button onClick={() => void saveNickname()} disabled={busy || !nickname.trim()}>{busy ? 'Guardando…' : 'Guardar apodo'}</button>
          </div>}
          {props.canManageChatWallpaper ? <>
            <h3>Fondo de tu cuenta</h3>
            <p>Se comparte con tus agentes y con los clientes de tus chats. Otros administradores no lo reciben ni pueden modificarlo.</p>
            <div className="wallpaper-options" role="group" aria-label="Fondos predeterminados">
              {CHAT_WALLPAPER_PRESETS.map((preset) => (
                <button key={preset} className={`wallpaper-choice wallpaper-preview-${preset}${props.chatWallpaper.kind === 'preset' && props.chatWallpaper.preset === preset ? ' selected' : ''}`} onClick={() => void chooseWallpaperPreset(preset)} disabled={busy || !props.selectedChatId} aria-pressed={props.chatWallpaper.kind === 'preset' && props.chatWallpaper.preset === preset}>
                  {wallpaperLabel(preset)}
                </button>
              ))}
            </div>
            <div className="wallpaper-upload">
              <button type="button" style={{ minHeight: 48, width: '100%', marginTop: 12 }} disabled={busy || !props.selectedChatId} onClick={() => wallpaperInput.current?.click()}>
                {props.chatWallpaper.kind === 'custom' ? 'Cambiar imagen de fondo' : 'Subir imagen de fondo'}
              </button>
              <input
                ref={wallpaperInput}
                type="file"
                accept="image/jpeg,image/png,image/webp,image/gif"
                hidden
                disabled={busy || !props.selectedChatId}
                onChange={(event) => {
                  const file = event.currentTarget.files?.[0] ?? null;
                  event.currentTarget.value = '';
                  void chooseWallpaperFile(file);
                }}
              />
            </div>
            <p>Tus clientes también verán este fondo.</p>
            <p className="muted">La imagen se cifra antes de subirla. Las fotos grandes se reducen en este dispositivo a un máximo de 3 MB; las imágenes pequeñas conservan su calidad. Elegir un preset reemplaza la imagen para toda tu cuenta.</p>
          </> : props.selectedChatId
            ? <p className="muted">Este chat pertenece a otra cuenta administrativa. Su fondo no se comparte con vos.</p>
            : <p className="muted">Seleccioná una conversación de tu cuenta para configurar el fondo.</p>}
        </section>}

        {activeSection === 'clients' && canIssueReferral && (
          <section className="security-section">
            <h3>Invitaciones al chat</h3>
            {referralWorkspaceIds.length > 1 && (
              <label>Equipo<select value={inviteWorkspaceId} onChange={(event) => setInviteWorkspaceId(event.target.value)}>{referralWorkspaceIds.map((id) => <option key={id} value={id}>{shortId(id)}</option>)}</select></label>
            )}
            <div className="reauth-card">
              <strong>Enlace personal para invitados</strong>
              <p>Compartilo individualmente o en grupos. Cada persona entra sin usuario ni contraseña y recibe un chat nuevo que ve todo el equipo. Ratchet registra quién difundió el enlace, pero no asigna la conversación.</p>
              <button onClick={() => void generateInvitation('REFERRAL')} disabled={busy}>{busy ? 'Generando…' : 'Generar enlace al chat'}</button>
            </div>
            {generatedInvitation && (
              <div className="reauth-card">
                <strong>{generatedInvitation.kind === 'ACCESS' ? 'Cuenta y enlace creados' : 'Enlace para invitados creado'}</strong>
                {generatedInvitation.loginName && <p>Usuario del cliente: <code>{generatedInvitation.loginName}</code></p>}
                <code>{generatedInvitation.url}</code>
                <p>{generatedInvitation.expiresAt ? `Vence: ${new Date(generatedInvitation.expiresAt).toLocaleString()}` : 'Sin vencimiento. Cada uso crea una conversación nueva y conserva la atribución de origen.'}</p>
                <button className="secondary" onClick={() => void copyInvitation()}>{copied ? 'Copiado' : 'Copiar enlace'}</button>
              </div>
            )}
          </section>
        )}

        {activeSection === 'devices' && <section className="security-section">
          <div className="section-heading"><div><h3>Navegadores conectados</h3><p>Desconectá cualquiera que no reconozcas. Para volver a usarlo habrá que ingresar otra vez.</p></div><button className="secondary" onClick={() => void refresh()} disabled={busy}>Actualizar</button></div>
          <div className="device-list">
            {devices.map((device) => {
              const current = device.device_id === props.session.device_id;
              return <article className="device-card" key={device.device_id}>
                <div className="device-card-main"><strong>{device.display_name}{current ? ' · este navegador' : ''}</strong><span>{device.revoked_at ? 'Desconectado' : device.authorized_at ? 'Conectado' : 'Esperando activación'}{device.crypto_ready ? ' · listo para mensajes seguros' : ' · preparando seguridad'}</span><details><summary>Ver identificación técnica</summary><code title={device.crypto_identity_public_key}>{deviceIdentityFingerprint(device.crypto_identity_public_key)}</code></details></div>
                <div className="device-actions">
                  {!device.revoked_at && <button className="danger-secondary" onClick={() => void prepareAction({ kind: 'revoke', device })} disabled={busy}>Desconectar</button>}
                </div>
              </article>;
            })}
          </div>
        </section>}

          </div>
        </div>
      </section>
    </div>
  );
}

function shortId(value: string): string {
  return value.slice(0, 8);
}

function staffRoleLabel(role: OperatorRecord['staff_role']): string {
  return { OWNER: 'Owner', ADMIN: 'Administrador', OPERATOR: 'Agente' }[role];
}

function wallpaperLabel(preset: ChatWallpaperPreset): string {
  return { default: 'Original', sand: 'Arena', sage: 'Verde suave', sky: 'Celeste' }[preset];
}

function describe(error: unknown): string { return friendlyError(error); }
