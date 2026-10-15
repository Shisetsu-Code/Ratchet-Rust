import { z } from 'zod';

export const MAX_WALLPAPER_PLAINTEXT_BYTES = 3 * 1024 * 1024;
export const MAX_WALLPAPER_CIPHERTEXT_BYTES = MAX_WALLPAPER_PLAINTEXT_BYTES + 16;
export const WALLPAPER_CRYPTO_PROTOCOL = 'ratchet-wallpaper-e2ee' as const;
export const WALLPAPER_CRYPTO_VERSION = 1 as const;

export const ChatWallpaperPresetSchema = z.enum(['default', 'sand', 'sage', 'sky']);
export const ChatWallpaperContentTypeSchema = z.enum(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);

const B64URL_32_SCHEMA = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const B64URL_24_SCHEMA = z.string().regex(/^[A-Za-z0-9_-]{32}$/);
const B64URL_48_SCHEMA = z.string().regex(/^[A-Za-z0-9_-]{64}$/);
const B64URL_64_SCHEMA = z.string().regex(/^[A-Za-z0-9_-]{86}$/);

export const WallpaperManifestSchema = z.object({
  protocol: z.literal(WALLPAPER_CRYPTO_PROTOCOL),
  version: z.literal(WALLPAPER_CRYPTO_VERSION),
  wallpaper_id: z.string().uuid(),
  workspace_id: z.string().uuid(),
  owner_admin_user_id: z.string().uuid(),
  signer_device_id: z.string().uuid(),
  content_type: ChatWallpaperContentTypeSchema,
  image_nonce_b64url: B64URL_24_SCHEMA,
  ciphertext_sha256_b64url: B64URL_32_SCHEMA,
});

export const WallpaperKeyEnvelopeSchema = z.object({
  recipient_user_id: z.string().uuid(),
  recipient_device_id: z.string().uuid(),
  ephemeral_public_key_b64url: B64URL_32_SCHEMA,
  nonce_b64url: B64URL_24_SCHEMA,
  wrapped_key_b64url: B64URL_48_SCHEMA,
});

export const WallpaperRecipientDeviceSchema = z.object({
  user_id: z.string().uuid(),
  device_id: z.string().uuid(),
  identity_public_key: B64URL_32_SCHEMA,
  device_certificate: z.string().nullable(),
  account_authorized: z.literal(true).optional(),
});

export const WallpaperRecipientSetResponseSchema = z.object({
  workspace_id: z.string().uuid(),
  owner_admin_user_id: z.string().uuid(),
  can_distribute: z.boolean(),
  current_wallpaper_id: z.string().uuid().nullable(),
  enveloped_device_ids: z.array(z.string().uuid()),
  devices: z.array(WallpaperRecipientDeviceSchema),
});

const SharedWallpaperBaseSchema = z.object({
  can_manage: z.boolean(),
  can_distribute: z.boolean(),
  updated_at: z.string().datetime().nullable(),
});

export const ChatWallpaperResponseSchema = z.discriminatedUnion('kind', [
  SharedWallpaperBaseSchema.extend({
    kind: z.literal('preset'),
    preset: ChatWallpaperPresetSchema,
  }),
  SharedWallpaperBaseSchema.extend({
    kind: z.literal('custom'),
    manifest: WallpaperManifestSchema,
    signature_b64url: B64URL_64_SCHEMA,
    image_path: z.string().startsWith('/api/v1/chats/'),
    key_envelope: WallpaperKeyEnvelopeSchema.nullable(),
  }),
]);

export const UpdateChatWallpaperRequestSchema = z.object({ preset: ChatWallpaperPresetSchema });

export const CommitCustomWallpaperRequestSchema = z.object({
  manifest: WallpaperManifestSchema,
  signature_b64url: B64URL_64_SCHEMA,
  envelopes: z.array(WallpaperKeyEnvelopeSchema).min(1).max(10_000),
});

export const AppendWallpaperEnvelopesRequestSchema = z.object({
  wallpaper_id: z.string().uuid(),
  envelopes: z.array(WallpaperKeyEnvelopeSchema).min(1).max(10_000),
});

export type ChatWallpaperPreset = z.infer<typeof ChatWallpaperPresetSchema>;
export type ChatWallpaperContentType = z.infer<typeof ChatWallpaperContentTypeSchema>;
export type ChatWallpaperResponse = z.infer<typeof ChatWallpaperResponseSchema>;
export type WallpaperManifest = z.infer<typeof WallpaperManifestSchema>;
export type WallpaperKeyEnvelope = z.infer<typeof WallpaperKeyEnvelopeSchema>;
export type WallpaperRecipientDevice = z.infer<typeof WallpaperRecipientDeviceSchema>;
export type WallpaperRecipientSetResponse = z.infer<typeof WallpaperRecipientSetResponseSchema>;
export type CommitCustomWallpaperRequest = z.infer<typeof CommitCustomWallpaperRequestSchema>;

export function wallpaperManifestSigningBytes(manifest: WallpaperManifest): Uint8Array {
  const value = WallpaperManifestSchema.parse(manifest);
  return new TextEncoder().encode(JSON.stringify({
    protocol: value.protocol,
    version: value.version,
    wallpaper_id: value.wallpaper_id,
    workspace_id: value.workspace_id,
    owner_admin_user_id: value.owner_admin_user_id,
    signer_device_id: value.signer_device_id,
    content_type: value.content_type,
    image_nonce_b64url: value.image_nonce_b64url,
    ciphertext_sha256_b64url: value.ciphertext_sha256_b64url,
  }));
}

export function wallpaperImageAad(input: {
  wallpaper_id: string;
  workspace_id: string;
  owner_admin_user_id: string;
  content_type: ChatWallpaperContentType;
}): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    protocol: WALLPAPER_CRYPTO_PROTOCOL,
    version: WALLPAPER_CRYPTO_VERSION,
    purpose: 'image-ciphertext',
    wallpaper_id: input.wallpaper_id,
    workspace_id: input.workspace_id,
    owner_admin_user_id: input.owner_admin_user_id,
    content_type: input.content_type,
  }));
}

export function wallpaperKeyEnvelopeAad(input: {
  wallpaper_id: string;
  workspace_id: string;
  owner_admin_user_id: string;
  recipient_user_id: string;
  recipient_device_id: string;
}): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    protocol: WALLPAPER_CRYPTO_PROTOCOL,
    version: WALLPAPER_CRYPTO_VERSION,
    purpose: 'content-key-envelope',
    wallpaper_id: input.wallpaper_id,
    workspace_id: input.workspace_id,
    owner_admin_user_id: input.owner_admin_user_id,
    recipient_user_id: input.recipient_user_id,
    recipient_device_id: input.recipient_device_id,
  }));
}
