-- Upgrade account wallpapers from server-readable AES metadata to
-- end-to-end per-device key envelopes without rewriting an already-applied 0019.
--
-- Existing custom wallpapers cannot be migrated cryptographically because the
-- new format requires a client signature and device-specific envelopes. Fail
-- closed to the default preset and erase the old server-readable key material.
UPDATE account_wallpapers
SET
  kind='PRESET',
  preset='default',
  object_key=NULL,
  content_type=NULL,
  encryption_key_b64url=NULL,
  nonce_b64url=NULL
WHERE kind='CUSTOM';

ALTER TABLE account_wallpapers ADD COLUMN wallpaper_id TEXT;
ALTER TABLE account_wallpapers ADD COLUMN image_nonce_b64url TEXT;
ALTER TABLE account_wallpapers ADD COLUMN ciphertext_sha256_b64url TEXT;
ALTER TABLE account_wallpapers ADD COLUMN signer_device_id TEXT;
ALTER TABLE account_wallpapers ADD COLUMN signature_b64url TEXT;
ALTER TABLE account_wallpapers ADD COLUMN key_envelopes_json TEXT;

CREATE UNIQUE INDEX idx_account_wallpapers_id
  ON account_wallpapers(wallpaper_id)
  WHERE wallpaper_id IS NOT NULL;
