import type { AccountPanelSection } from './AccountSecurityPanel';
import { useEffect, useRef } from 'react';

type MenuEntry = { section: AccountPanelSection; label: string; detail: string };

export function AppOptionsMenu(props: {
  canManageAgents: boolean;
  canCreateReferrals: boolean;
  notificationsEnabled: boolean;
  notificationsBusy?: boolean;
  notificationMessage?: string | null;
  onOpenSection: (section: AccountPanelSection) => void;
  onEnableNotifications: () => void;
  onLogout: () => void;
  onClose: () => void;
}) {
  const menuRef = useRef<HTMLElement>(null);
  const closeRef = useRef(props.onClose);
  closeRef.current = props.onClose;
  useEffect(() => {
    menuRef.current?.querySelector<HTMLButtonElement>('button')?.focus();
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') closeRef.current(); };
    document.addEventListener('keydown', closeOnEscape);
    return () => document.removeEventListener('keydown', closeOnEscape);
  }, []);

  const administration: MenuEntry[] = [
    ...(props.canCreateReferrals ? [{
      section: 'clients' as const,
      label: 'Invitaciones al chat',
      detail: 'Generar enlaces para recibir invitados',
    }] : []),
    ...(props.canManageAgents ? [{ section: 'agents' as const, label: 'Agentes', detail: 'Crear, conectar y desconectar tus agentes' }] : []),
  ];

  return (
    <div className="app-menu-backdrop" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) props.onClose();
    }}>
      <nav ref={menuRef} className="app-options-menu" role="dialog" aria-modal="true" aria-label="Opciones de Ratchet">
        <header><div><strong>Opciones</strong><span>Administración y preferencias</span></div><button className="icon-button" onClick={props.onClose} aria-label="Cerrar opciones">×</button></header>
        {administration.length > 0 && <section><h2>Administración</h2>
          {administration.map((entry) => <MenuButton key={entry.section} label={entry.label} detail={entry.detail} onClick={() => props.onOpenSection(entry.section)} />)}
        </section>}
        <section><h2>Cuenta y aplicación</h2>
          <MenuButton label="Apariencia" detail="Fondo y presentación del chat" onClick={() => props.onOpenSection('appearance')} />
          <MenuButton label="Dispositivos" detail="Navegadores conectados a la cuenta" onClick={() => props.onOpenSection('devices')} />
          <MenuButton label={props.notificationsBusy ? 'Activando…' : props.notificationsEnabled ? 'Notificaciones activas' : 'Activar notificaciones'} detail="Avisos de mensajes nuevos" onClick={props.onEnableNotifications} disabled={props.notificationsEnabled || props.notificationsBusy === true} />
          {props.notificationMessage && <p className="notice" role="status">{props.notificationMessage}</p>}
        </section>
        <button className="app-menu-logout" onClick={props.onLogout}>Cerrar sesión</button>
      </nav>
    </div>
  );
}

function MenuButton(props: { label: string; detail: string; onClick: () => void; disabled?: boolean }) {
  return <button className="app-menu-entry" onClick={props.onClick} disabled={props.disabled}>
    <span><strong>{props.label}</strong><small>{props.detail}</small></span><b aria-hidden="true">›</b>
  </button>;
}
