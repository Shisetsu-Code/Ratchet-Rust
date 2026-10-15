import type { IDBPDatabase } from 'idb';
import type { JsonSetting, LocalDbSchema } from '../storage/schema';

const GUEST_DEVICE_PREFIX = 'guest-account-device:';

export async function markGuestDevice(db: IDBPDatabase<LocalDbSchema>, deviceId: string): Promise<void> {
  await db.put('settings', {
    key: `${GUEST_DEVICE_PREFIX}${deviceId}`,
    kind: 'json',
    value: deviceId,
  } satisfies JsonSetting);
}

export async function loadGuestDeviceIds(db: IDBPDatabase<LocalDbSchema>): Promise<string[]> {
  const settings = await db.getAll('settings');
  return settings
    .filter((setting): setting is JsonSetting => setting.kind === 'json' && setting.key.startsWith(GUEST_DEVICE_PREFIX))
    .map((setting) => setting.value)
    .filter((value): value is string => typeof value === 'string');
}

export async function clearGuestDeviceMarker(db: IDBPDatabase<LocalDbSchema>, deviceId: string): Promise<void> {
  await db.delete('settings', `${GUEST_DEVICE_PREFIX}${deviceId}`);
}
