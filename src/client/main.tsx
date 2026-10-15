import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { AccessApp } from './invitations/AccessApp';
import { AgentAccessApp } from './invitations/AgentAccessApp';
import { LeadAccessApp } from './invitations/LeadAccessApp';
import { ReferralApp } from './invitations/ReferralApp';
import { SecureApp } from './app/SecureApp';
import { registerPwaServiceWorker } from './pwa/register';

const root = document.getElementById('root');
if (!root) throw new Error('Missing #root');

const fragment = new URLSearchParams(window.location.hash.slice(1));
const agentToken = fragment.get('agent');
const accessToken = fragment.get('access');
const referralToken = fragment.get('referral');
const leadToken = fragment.get('lead');
if (agentToken || leadToken || fragment.has('bootstrap')) {
  history.replaceState(null, '', window.location.pathname + window.location.search);
}
const application = agentToken
  ? <AgentAccessApp token={agentToken} />
  : leadToken
    ? <LeadAccessApp token={leadToken} />
  : accessToken
    ? <AccessApp token={accessToken} />
    : referralToken
      ? <ReferralApp token={referralToken} />
      : <SecureApp />;

createRoot(root).render(<StrictMode>{application}</StrictMode>);
void registerPwaServiceWorker();
