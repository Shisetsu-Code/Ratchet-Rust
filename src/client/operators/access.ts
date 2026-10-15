import type { IDBPDatabase } from 'idb';
import { ClaimOperatorAccessResponseSchema } from '../../shared/contracts/operators';
import { uuidv7 } from '../../shared/ids/uuidv7';
import { disposeDeviceIdentity, generateDeviceIdentity, persistGeneratedDeviceIdentity } from '../crypto/key-vault/identity';
import { bytesToBase64Url } from '../crypto/local-state/base64url';
import type { LocalDbSchema } from '../storage/schema';
import { apiFetch } from '../transport/api';

export async function claimOperatorAccess(
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
    return await apiFetch('/api/v1/operator-access/claim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_token: token,
        device: {
          device_id: deviceId,
          display_name: deviceName.trim() || 'Navegador',
          crypto_identity_public_key: bytesToBase64Url(generated.keyPair.publicKey),
        },
      }),
    }, (value) => ClaimOperatorAccessResponseSchema.parse(value), { retryMode: 'none' });
  } catch (error) {
    if (persisted) await db.delete('device_identity', deviceId).catch(() => undefined);
    throw error;
  } finally {
    disposeDeviceIdentity(generated);
  }
}
