import type { IDBPDatabase } from 'idb';
import type { CurrentSessionResponse } from '../../shared/contracts/session';
import {
  ChatWallpaperResponseSchema,
  MAX_WALLPAPER_CIPHERTEXT_BYTES,
  WallpaperRecipientSetResponseSchema,
  type ChatWallpaperResponse,
  type WallpaperRecipientSetResponse,
} from '../../shared/contracts/wallpaper';
import type { LocalDbSchema } from '../storage/schema';
import { ApiError, apiFetch } from '../transport/api';
import { readResponseBytes } from '../transport/bounded-bytes';
import {
  createMissingWallpaperKeyEnvelopes,
  openEncryptedWallpaper,
  prepareEncryptedWallpaper,
  unwrapVerifiedWallpaperContentKey,
} from './wallpaper-crypto';
import {
  DEFAULT_CHAT_WALLPAPER,
  wallpaperFromFile,
  type ChatWallpaper,
  type ChatWallpaperPreset,
} from './wallpaper';

import { prepareWallpaperImage } from './prepare-wallpaper';
export type SharedWallpaperResult = {
  wallpaper: ChatWallpaper;
  canManage: boolean;
  canDistribute: boolean;
  updatedAt: string | null;
  wallpaperId: string | null;
};

export async function getSharedChatWallpaper(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  chatId: string,
  previous?: SharedWallpaperResult,
): Promise<SharedWallpaperResult> {
  const descriptor = await getWallpaperDescriptor(chatId);
  if (descriptor.kind === 'preset') {
    return {
      wallpaper: { kind: 'preset', preset: descriptor.preset },
      canManage: descriptor.can_manage,
      canDistribute: descriptor.can_distribute,
      updatedAt: descriptor.updated_at,
      wallpaperId: null,
    };
  }

  if (!descriptor.key_envelope) {
    return {
      wallpaper: DEFAULT_CHAT_WALLPAPER,
      canManage: descriptor.can_manage,
      canDistribute: descriptor.can_distribute,
      updatedAt: descriptor.updated_at,
      wallpaperId: descriptor.manifest.wallpaper_id,
    };
  }

  if (previous?.wallpaper.kind === 'custom'
    && previous.wallpaperId === descriptor.manifest.wallpaper_id) {
    if (descriptor.can_distribute) {
      void reconcileWallpaperEnvelopes(db, session, chatId, descriptor).catch(() => undefined);
    }
    return {
      wallpaper: previous.wallpaper,
      canManage: descriptor.can_manage,
      canDistribute: descriptor.can_distribute,
      updatedAt: descriptor.updated_at,
      wallpaperId: descriptor.manifest.wallpaper_id,
    };
  }

  const ciphertext = await fetchWallpaperCiphertext(descriptor.image_path);
  let opened: Awaited<ReturnType<typeof openEncryptedWallpaper>> | undefined;
  try {
    opened = await openEncryptedWallpaper(db, session, chatId, descriptor, ciphertext);
    const wallpaper = await wallpaperFromFile(opened.file);
    if (descriptor.can_distribute) {
      await reconcileWallpaperEnvelopesWithKey(db, session, chatId, descriptor, opened.contentKey).catch(() => undefined);
    }
    return {
      wallpaper,
      canManage: descriptor.can_manage,
      canDistribute: descriptor.can_distribute,
      updatedAt: descriptor.updated_at,
      wallpaperId: descriptor.manifest.wallpaper_id,
    };
  } finally {
    ciphertext.fill(0);
    opened?.contentKey.fill(0);
  }
}

export async function setSharedChatWallpaper(
  chatId: string,
  preset: ChatWallpaperPreset,
): Promise<SharedWallpaperResult> {
  const descriptor = await apiFetch(
    `/api/v1/chats/${encodeURIComponent(chatId)}/wallpaper`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset }),
    },
    (value) => ChatWallpaperResponseSchema.parse(value),
    { retryMode: 'none' },
  );
  if (descriptor.kind !== 'preset') throw new Error('Wallpaper preset update returned an invalid response');
  return {
    wallpaper: { kind: 'preset', preset: descriptor.preset },
    canManage: descriptor.can_manage,
    canDistribute: descriptor.can_distribute,
    updatedAt: descriptor.updated_at,
    wallpaperId: null,
  };
}

export async function setSharedCustomChatWallpaper(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  chatId: string,
  inputFile: File,
): Promise<SharedWallpaperResult> {
  const file = await prepareWallpaperImage(inputFile);
  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const recipients = await getWallpaperRecipients(chatId);
    const prepared = await prepareEncryptedWallpaper(db, session, recipients, file);
    try {
      await apiFetch(
        `/api/v1/chats/${encodeURIComponent(chatId)}/wallpaper/uploads/${encodeURIComponent(prepared.wallpaperId)}/image`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/octet-stream' },
          body: prepared.ciphertext.slice().buffer,
        },
        (value) => {
          if (value !== null) throw new Error('Expected empty wallpaper upload response');
        },
        { retryMode: 'idempotent', timeoutMs: 20_000 },
      );

      const descriptor = await apiFetch(
        `/api/v1/chats/${encodeURIComponent(chatId)}/wallpaper/uploads/${encodeURIComponent(prepared.wallpaperId)}/commit`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            manifest: prepared.manifest,
            signature_b64url: prepared.signatureB64Url,
            envelopes: prepared.envelopes,
          }),
        },
        (value) => ChatWallpaperResponseSchema.parse(value),
        { retryMode: 'none', timeoutMs: 20_000 },
      );
      if (descriptor.kind !== 'custom') throw new Error('Custom wallpaper commit returned an invalid response');

      return {
        wallpaper: await wallpaperFromFile(file),
        canManage: descriptor.can_manage,
        canDistribute: descriptor.can_distribute,
        updatedAt: descriptor.updated_at,
        wallpaperId: descriptor.manifest.wallpaper_id,
      };
    } catch (error) {
      lastError = error;
      if (!(error instanceof ApiError && error.type === 'WALLPAPER_RECIPIENT_SET_STALE' && attempt === 0)) throw error;
    } finally {
      prepared.ciphertext.fill(0);
    }
  }
  throw lastError instanceof Error ? lastError : new Error('Unable to commit custom wallpaper');
}

async function getWallpaperDescriptor(chatId: string): Promise<ChatWallpaperResponse> {
  return apiFetch(
    `/api/v1/chats/${encodeURIComponent(chatId)}/wallpaper`,
    {},
    (value) => ChatWallpaperResponseSchema.parse(value),
  );
}

async function getWallpaperRecipients(chatId: string): Promise<WallpaperRecipientSetResponse> {
  return apiFetch(
    `/api/v1/chats/${encodeURIComponent(chatId)}/wallpaper/recipients`,
    {},
    (value) => WallpaperRecipientSetResponseSchema.parse(value),
  );
}

async function fetchWallpaperCiphertext(path: string): Promise<Uint8Array> {
  const response = await fetch(path, {
    method: 'GET',
    cache: 'no-store',
    credentials: 'include',
    headers: { 'X-Request-ID': crypto.randomUUID() },
  });
  if (!response.ok) throw new Error(`Unable to load shared wallpaper (${response.status})`);
  return readResponseBytes(response, MAX_WALLPAPER_CIPHERTEXT_BYTES);
}

async function reconcileWallpaperEnvelopes(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  chatId: string,
  descriptor: Extract<ChatWallpaperResponse, { kind: 'custom' }>,
): Promise<void> {
  const contentKey = await unwrapVerifiedWallpaperContentKey(db, session, chatId, descriptor);
  try {
    await reconcileWallpaperEnvelopesWithKey(db, session, chatId, descriptor, contentKey);
  } finally {
    contentKey.fill(0);
  }
}

async function reconcileWallpaperEnvelopesWithKey(
  db: IDBPDatabase<LocalDbSchema>,
  session: CurrentSessionResponse,
  chatId: string,
  descriptor: Extract<ChatWallpaperResponse, { kind: 'custom' }>,
  contentKey: Uint8Array,
): Promise<void> {
  if (!descriptor.can_distribute) return;
  const recipients = await getWallpaperRecipients(chatId);
  const missing = await createMissingWallpaperKeyEnvelopes(
    db,
    session,
    recipients,
    descriptor.manifest,
    contentKey,
  );
  if (missing.length === 0) return;

  await apiFetch(
    `/api/v1/chats/${encodeURIComponent(chatId)}/wallpaper/${encodeURIComponent(descriptor.manifest.wallpaper_id)}/envelopes`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallpaper_id: descriptor.manifest.wallpaper_id,
        envelopes: missing,
      }),
    },
    (value) => {
      if (value !== null) throw new Error('Expected empty wallpaper envelope response');
    },
    { retryMode: 'idempotent' },
  );
}
