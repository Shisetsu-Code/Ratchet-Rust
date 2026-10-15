import { useState } from 'react';
import { SecureApp } from '../app/SecureApp';
import { ApiError } from '../transport/api';
import { claimReferral } from './api';
import './referral.css';

type ReferralState = 'IDLE' | 'CLAIMING' | 'LOGIN_REQUIRED' | 'ERROR';

export function ReferralApp(props: { token: string }) {
  const [state, setState] = useState<ReferralState>('IDLE');
  const [error, setError] = useState<string | null>(null);

  const claim = async () => {
    setState('CLAIMING');
    setError(null);
    try {
      const result = await claimReferral(props.token);
      window.location.replace(`/?chat=${encodeURIComponent(result.chat_id)}`);
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 401) {
        setState('LOGIN_REQUIRED');
        return;
      }
      setError(cause instanceof Error ? cause.message : 'No se pudo vincular la invitación');
      setState('ERROR');
    }
  };

  return (
    <>
      <SecureApp />
      <aside className="referral-link-card" aria-live="polite">
        <div>
          <strong>Invitación de administrador</strong>
          <p>
            {state === 'LOGIN_REQUIRED'
              ? 'Iniciá sesión con tu cuenta CUSTOMER y después confirmá la vinculación.'
              : 'Vinculá esta cuenta con el administrador que compartió el enlace. Se creará un chat independiente.'}
          </p>
          {error && <p className="referral-link-error">{error}</p>}
        </div>
        <button onClick={() => void claim()} disabled={state === 'CLAIMING'}>
          {state === 'CLAIMING' ? 'Vinculando…' : state === 'LOGIN_REQUIRED' ? 'Ya inicié sesión · vincular' : 'Vincular cuenta'}
        </button>
      </aside>
    </>
  );
}
