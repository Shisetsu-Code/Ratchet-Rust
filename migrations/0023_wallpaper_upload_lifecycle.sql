-- Durable tombstones prevent an old wallpaper ID from being uploaded or
-- published again while asynchronous object cleanup is in progress.
CREATE TABLE wallpaper_uploads (
  object_key TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  owner_admin_user_id TEXT NOT NULL,
  wallpaper_id TEXT NOT NULL UNIQUE,
  device_id TEXT NOT NULL,
  ciphertext_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('UPLOADING','READY','COMMITTED','RETIRED','ABORTED')),
  expires_at TEXT NOT NULL,
  cleaned_at TEXT
);
CREATE INDEX idx_wallpaper_uploads_cleanup ON wallpaper_uploads(state,expires_at);
INSERT INTO wallpaper_uploads
SELECT object_key,workspace_id,owner_admin_user_id,wallpaper_id,signer_device_id,
  ciphertext_sha256_b64url,'COMMITTED',updated_at,NULL
FROM account_wallpapers WHERE kind='CUSTOM' AND wallpaper_id IS NOT NULL AND object_key IS NOT NULL;

CREATE TRIGGER wallpaper_publish_insert BEFORE INSERT ON account_wallpapers
WHEN NEW.kind='CUSTOM'
BEGIN
  SELECT (CASE WHEN NOT EXISTS (SELECT 1 FROM wallpaper_uploads u
    WHERE u.object_key=NEW.object_key AND u.wallpaper_id=NEW.wallpaper_id
      AND u.workspace_id=NEW.workspace_id AND u.owner_admin_user_id=NEW.owner_admin_user_id
      AND u.device_id=NEW.signer_device_id AND u.ciphertext_hash=NEW.ciphertext_sha256_b64url
      AND ((u.state='READY' AND u.expires_at>strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        OR (u.state='COMMITTED' AND EXISTS (SELECT 1 FROM account_wallpapers a WHERE a.object_key=u.object_key))))
    THEN RAISE(ABORT,'Wallpaper upload is not publishable') END);
END;
CREATE TRIGGER wallpaper_publish_update BEFORE UPDATE ON account_wallpapers
WHEN NEW.kind='CUSTOM' AND (OLD.object_key IS NOT NEW.object_key OR OLD.wallpaper_id IS NOT NEW.wallpaper_id)
BEGIN
  SELECT (CASE WHEN NOT EXISTS (SELECT 1 FROM wallpaper_uploads u
    WHERE u.object_key=NEW.object_key AND u.wallpaper_id=NEW.wallpaper_id
      AND u.workspace_id=NEW.workspace_id AND u.owner_admin_user_id=NEW.owner_admin_user_id
      AND u.device_id=NEW.signer_device_id AND u.ciphertext_hash=NEW.ciphertext_sha256_b64url
      AND u.state='READY' AND u.expires_at>strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    THEN RAISE(ABORT,'Wallpaper upload is not publishable') END);
END;
CREATE TRIGGER wallpaper_commit_insert AFTER INSERT ON account_wallpapers
WHEN NEW.kind='CUSTOM'
BEGIN
  UPDATE wallpaper_uploads SET state='COMMITTED' WHERE object_key=NEW.object_key;
END;
CREATE TRIGGER wallpaper_commit_update AFTER UPDATE ON account_wallpapers
BEGIN
  UPDATE wallpaper_uploads SET state='RETIRED' WHERE object_key=OLD.object_key AND OLD.object_key IS NOT NEW.object_key;
  UPDATE wallpaper_uploads SET state='COMMITTED' WHERE object_key=NEW.object_key AND NEW.kind='CUSTOM';
END;
CREATE TRIGGER wallpaper_retire_delete AFTER DELETE ON account_wallpapers
BEGIN
  UPDATE wallpaper_uploads SET state='RETIRED' WHERE object_key=OLD.object_key;
END;
