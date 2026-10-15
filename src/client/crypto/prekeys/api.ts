import {
  ConsumePrekeyResponseSchema,
  DeviceBundleDiscoveryResponseSchema,
  PrekeyStatusResponseSchema,
  type ConsumePrekeyRequest,
  type ConsumePrekeyResponse,
  type DeviceBundleDiscoveryResponse,
  type PrekeyStatusResponse,
  type PublishPrekeysRequest,
} from '../../../shared/contracts/prekeys';
import { apiFetch } from '../../transport/api';

export async function publishPrekeysHttp(request: PublishPrekeysRequest): Promise<void> {
  await apiFetch(
    '/api/v1/crypto/prekeys',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    },
    (value) => {
      if (value !== null) throw new Error('Expected empty prekey publication response');
    },
    { retryMode: 'idempotent' },
  );
}

export async function getOwnPrekeyStatus(): Promise<PrekeyStatusResponse> {
  return apiFetch('/api/v1/crypto/prekeys/status', {}, (value) => PrekeyStatusResponseSchema.parse(value));
}

export async function discoverPrekeyBundles(
  userId: string,
  chatId: string,
): Promise<DeviceBundleDiscoveryResponse> {
  return apiFetch(
    `/api/v1/crypto/devices/${encodeURIComponent(userId)}/bundle?chat_id=${encodeURIComponent(chatId)}`,
    {},
    (value) => DeviceBundleDiscoveryResponseSchema.parse(value),
  );
}

export async function consumePrekeysHttp(request: ConsumePrekeyRequest): Promise<ConsumePrekeyResponse> {
  return apiFetch(
    '/api/v1/crypto/prekeys/consume',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    },
    (value) => ConsumePrekeyResponseSchema.parse(value),
    { retryMode: 'none' },
  );
}
