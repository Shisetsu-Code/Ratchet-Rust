import type { IDBPDatabase } from 'idb';
import {
  ClaimLeadResponseSchema,
  ClaimCustomerAccessResponseSchema,
  CreateGuestAccountResponseSchema,
  type CreateGuestAccountRequest,
} from '../../shared/contracts/leads';
import { uuidv7 } from '../../shared/ids/uuidv7';
import { disposeDeviceIdentity, generateDeviceIdentity, persistGeneratedDeviceIdentity } from '../crypto/key-vault/identity';
import { bytesToBase64Url } from '../crypto/local-state/base64url';
import type { LocalDbSchema } from '../storage/schema';
import { apiFetch } from '../transport/api';
import { clearGuestDeviceMarker, markGuestDevice } from '../auth/guest-device';

export async function claimLeadAccess(
  db: IDBPDatabase<LocalDbSchema>,
  token: string,
  deviceName: string,
) {
  const deviceId = uuidv7();
  const generated = await generateDeviceIdentity();
  let persisted = false;
  try {
    await persistGeneratedDeviceIdentity(db, deviceId, generated);
    persisted = true;
    await markGuestDevice(db, deviceId);
    const result = await apiFetch('/api/v1/lead-access/claim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        invitation_token: token,
        device: {
          device_id: deviceId,
          display_name: deviceName.trim() || 'Navegador del invitado',
          crypto_identity_public_key: bytesToBase64Url(generated.keyPair.publicKey),
        },
      }),
    }, (value) => ClaimLeadResponseSchema.parse(value), { retryMode: 'none' });
    return result;
  } catch (error) {
    if (persisted) {
      await clearGuestDeviceMarker(db, deviceId).catch(() => undefined);
      await db.delete('device_identity', deviceId).catch(() => undefined);
    }
    throw error;
  } finally {
    disposeDeviceIdentity(generated);
  }
}

export async function createGuestAccount(chatId: string, input: CreateGuestAccountRequest) {
  return apiFetch(`/api/v1/leads/${encodeURIComponent(chatId)}/account`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  }, (value) => CreateGuestAccountResponseSchema.parse(value), { retryMode: 'none' });
}

export async function createCustomerAccess(chatId: string) {
  return apiFetch(`/api/v1/leads/${encodeURIComponent(chatId)}/access`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
  }, (value) => CreateGuestAccountResponseSchema.parse(value), { retryMode: 'none' });
}

export async function setCustomerPassword(chatId: string, loginName: string, password: string) {
  return apiFetch(`/api/v1/leads/${encodeURIComponent(chatId)}/account/password`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ login_name: loginName, password }),
  }, (value) => value, { retryMode: 'none' });
}

export async function claimCustomerAccess(db: IDBPDatabase<LocalDbSchema>, token: string, deviceName: string) {
  const deviceId = uuidv7();
  const generated = await generateDeviceIdentity();
  let persisted = false;
  let claimed = false;
  try {
    await persistGeneratedDeviceIdentity(db, deviceId, generated);
    persisted = true;
    const result = await apiFetch('/api/v1/lead-access/customer/claim', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_token: token, device: {
        device_id: deviceId, display_name: deviceName.trim() || 'Navegador del cliente',
        crypto_identity_public_key: bytesToBase64Url(generated.keyPair.publicKey),
      } }),
    }, (value) => ClaimCustomerAccessResponseSchema.parse(value), { retryMode: 'none' });
    claimed = true;
    // This origin can retain encrypted cache from a previous identity. It must
    // never be opened with the newly generated device key.
    try {
      const cached = await db.getAllFromIndex('encrypted_cache', 'by-chat', result.chat_id);
      const tx = db.transaction(['encrypted_cache', 'settings'], 'readwrite');
      for (const record of cached) await tx.objectStore('encrypted_cache').delete(record.cache_key);
      await tx.objectStore('settings').delete(`sync:${result.chat_id}`);
      await tx.done;
    } catch {
      // The one-use token is already consumed. Do not turn a successful claim
      // into a false failure; the first sync can safely replace stale records.
    }
    return result;
  } catch (error) {
    if (persisted && !claimed) await db.delete('device_identity', deviceId).catch(() => undefined);
    throw error;
  } finally { disposeDeviceIdentity(generated); }
}
