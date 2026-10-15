import { PushConfigResponseSchema, PushRegistrationResponseSchema } from '../../shared/contracts/push';
import { apiFetch } from '../transport/api';

export async function getPushConfiguration() {
  return apiFetch('/api/v1/push/config', {}, (value) => PushConfigResponseSchema.parse(value));
}

export async function enablePushNotifications(registration: ServiceWorkerRegistration, grantedPermission?: NotificationPermission): Promise<{ enabled: boolean; subscription_id?: string }> {
  const permission = grantedPermission ?? await Notification.requestPermission();
  if (permission !== 'granted') return { enabled: false };
  const config = await getPushConfiguration();
  if (!config.enabled || !config.application_server_key) return { enabled: false };
  let subscription = await registration.pushManager.getSubscription();
  if (!subscription) {
    subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: base64UrlToArrayBuffer(config.application_server_key),
    });
  }
  const json = subscription.toJSON();
  if (!json.endpoint || !json.keys?.p256dh || !json.keys.auth) throw new Error('Browser returned an incomplete PushSubscription');
  const registered = await apiFetch('/api/v1/push/subscriptions', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ endpoint: json.endpoint, expirationTime: json.expirationTime ?? null, keys: { p256dh: json.keys.p256dh, auth: json.keys.auth } }),
  }, (value) => PushRegistrationResponseSchema.parse(value), { retryMode: 'idempotent' });
  return { enabled: true, subscription_id: registered.subscription_id };
}

export async function disablePushNotifications(registration: ServiceWorkerRegistration, subscriptionId?: string): Promise<void> {
  if (subscriptionId) await apiFetch(`/api/v1/push/subscriptions/${subscriptionId}`, { method: 'DELETE' }, () => undefined, { retryMode: 'idempotent' });
  const subscription = await registration.pushManager.getSubscription();
  if (subscription) await subscription.unsubscribe();
}

function base64UrlToArrayBuffer(value: string): ArrayBuffer {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0)).buffer;
}
