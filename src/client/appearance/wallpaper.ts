import type { IDBPDatabase } from 'idb';
import type { LocalDbSchema } from '../storage/schema';
import { validateWallpaperFile } from '../attachments/policy';

export const CHAT_WALLPAPER_SETTING_KEY = 'chat-wallpaper-v1';

export const CHAT_WALLPAPER_PRESETS = ['default', 'sand', 'sage', 'sky'] as const;
export type ChatWallpaperPreset = typeof CHAT_WALLPAPER_PRESETS[number];
export type ChatWallpaper = { kind: 'preset'; preset: ChatWallpaperPreset } | { kind: 'custom'; dataUrl: string };
export const DEFAULT_CHAT_WALLPAPER: ChatWallpaper = { kind: 'preset', preset: 'default' };

export async function loadChatWallpaper(db: IDBPDatabase<LocalDbSchema>): Promise<ChatWallpaper> {
  const record = await db.get('settings', CHAT_WALLPAPER_SETTING_KEY);
  if (!record || record.kind !== 'json') return DEFAULT_CHAT_WALLPAPER;
  return parseChatWallpaper(record.value);
}

export async function saveChatWallpaper(db: IDBPDatabase<LocalDbSchema>, wallpaper: ChatWallpaper): Promise<void> {
  const safe = parseChatWallpaper(wallpaper);
  await db.put('settings', { key: CHAT_WALLPAPER_SETTING_KEY, kind: 'json', value: safe });
}

export function parseChatWallpaper(value: unknown): ChatWallpaper {
  if (!value || typeof value !== 'object') return DEFAULT_CHAT_WALLPAPER;
  const candidate = value as Record<string, unknown>;
  if (candidate.kind === 'preset' && typeof candidate.preset === 'string' && CHAT_WALLPAPER_PRESETS.includes(candidate.preset as ChatWallpaperPreset)) {
    return { kind: 'preset', preset: candidate.preset as ChatWallpaperPreset };
  }
  if (candidate.kind === 'custom' && typeof candidate.dataUrl === 'string' && isSafeWallpaperDataUrl(candidate.dataUrl)) {
    return { kind: 'custom', dataUrl: candidate.dataUrl };
  }
  return DEFAULT_CHAT_WALLPAPER;
}

export async function wallpaperFromFile(file: File): Promise<ChatWallpaper> {
  const type = await validateWallpaperFile(file);
  const dataUrl = await readAsDataUrl(file);
  const canonical = `data:${type};base64,${dataUrl.slice(dataUrl.indexOf(',') + 1)}`;
  if (!isSafeWallpaperDataUrl(canonical)) throw new Error('No se pudo guardar la imagen de fondo.');
  return { kind: 'custom', dataUrl: canonical };
}

export function wallpaperClassName(wallpaper: ChatWallpaper): string {
  return wallpaper.kind === 'preset' ? `wallpaper-${wallpaper.preset}` : 'wallpaper-custom';
}

function isSafeWallpaperDataUrl(value: string): boolean {
  return /^data:image\/(?:jpeg|png|webp|gif);base64,[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length <= 4_200_000;
}

function readAsDataUrl(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('No se pudo leer la imagen de fondo.'));
    reader.onload = () => typeof reader.result === 'string' ? resolve(reader.result) : reject(new Error('No se pudo leer la imagen de fondo.'));
    reader.readAsDataURL(file);
  });
}
