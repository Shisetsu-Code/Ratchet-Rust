-- Additive migration: retain existing objects and charge them before admitting growth.
CREATE TABLE storage_limits (
  kind TEXT PRIMARY KEY,
  owner_bytes INTEGER NOT NULL,
  owner_objects INTEGER NOT NULL,
  global_bytes INTEGER NOT NULL,
  global_objects INTEGER NOT NULL
);
INSERT INTO storage_limits VALUES
 ('attachment',1073741824,10000,107374182400,1000000),
 ('wallpaper',25165952,8,10737418240,100000);
ALTER TABLE attachment_uploads ADD COLUMN cleaned_at TEXT;
ALTER TABLE attachment_uploads ADD COLUMN write_token TEXT;
ALTER TABLE attachment_uploads ADD COLUMN cleanup_after TEXT NOT NULL DEFAULT '';
ALTER TABLE attachment_uploads ADD COLUMN cleanup_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE attachment_uploads ADD COLUMN quota_size INTEGER CHECK(quota_size IS NULL OR quota_size>=size);
-- Old part admission permitted two maximum parts regardless of declared size.
-- Keep the protocol size unchanged and reserve that physical maximum for uploads
-- whose completed object size was never verified. New rows default to exact size.
UPDATE attachment_uploads SET quota_size=MAX(size,10485792) WHERE status NOT IN ('READY','COMMITTED');
ALTER TABLE wallpaper_uploads ADD COLUMN size INTEGER NOT NULL DEFAULT 3145744 CHECK(size>=0);
ALTER TABLE wallpaper_uploads ADD COLUMN write_token TEXT;
ALTER TABLE wallpaper_uploads ADD COLUMN upload_id TEXT;
ALTER TABLE wallpaper_uploads ADD COLUMN cleanup_after TEXT NOT NULL DEFAULT '';
ALTER TABLE wallpaper_uploads ADD COLUMN cleanup_attempts INTEGER NOT NULL DEFAULT 0;
-- Existing wallpapers had no size ledger. Charge the protocol maximum until rechecked.
-- Recheck historical cleanup, since the old cleaner could race an unfinished PUT.
UPDATE wallpaper_uploads SET cleaned_at=NULL;
CREATE TABLE object_storage_usage (
 kind TEXT NOT NULL,
 owner_id TEXT NOT NULL,
 bytes INTEGER NOT NULL CHECK(bytes>=0),
 objects INTEGER NOT NULL CHECK(objects>=0),
 pending INTEGER NOT NULL CHECK(pending>=0),
 records INTEGER NOT NULL CHECK(records>=0),
 PRIMARY KEY(kind,owner_id)
);
INSERT INTO object_storage_usage
 SELECT 'attachment',owner_user_id,SUM(COALESCE(quota_size,size)),COUNT(*),SUM(status<>'COMMITTED'),COUNT(*)
 FROM attachment_uploads GROUP BY owner_user_id;
INSERT INTO object_storage_usage
 SELECT 'wallpaper',owner_admin_user_id,SUM(size),COUNT(*),0,COUNT(*)
 FROM wallpaper_uploads GROUP BY owner_admin_user_id;
INSERT INTO object_storage_usage
 SELECT kind,'*',SUM(bytes),SUM(objects),SUM(pending),SUM(records)
 FROM object_storage_usage GROUP BY kind;
CREATE INDEX idx_attachment_cleanup_safe ON attachment_uploads(cleaned_at,cleanup_after,expires_at);
CREATE INDEX idx_wallpaper_cleanup_safe ON wallpaper_uploads(cleaned_at,cleanup_after,expires_at);
CREATE TRIGGER attachment_cleanup_fence BEFORE UPDATE OF cleaned_at ON attachment_uploads
 WHEN NEW.cleaned_at IS NOT NULL AND (NEW.write_token IS NOT NULL OR NEW.status<>'EXPIRED')
 BEGIN SELECT RAISE(ABORT,'ATTACHMENT_WRITE_IN_PROGRESS'); END;
CREATE TRIGGER wallpaper_cleanup_fence BEFORE UPDATE OF cleaned_at ON wallpaper_uploads
 WHEN NEW.cleaned_at IS NOT NULL AND (NEW.write_token IS NOT NULL OR NEW.state NOT IN ('ABORTED','RETIRED'))
 BEGIN SELECT RAISE(ABORT,'WALLPAPER_WRITE_IN_PROGRESS'); END;
CREATE TRIGGER attachment_storage_identity BEFORE UPDATE OF owner_user_id,size,object_key ON attachment_uploads
 WHEN NEW.owner_user_id<>OLD.owner_user_id OR NEW.size<>OLD.size OR NEW.object_key<>OLD.object_key
 BEGIN SELECT RAISE(ABORT,'ATTACHMENT_STORAGE_IDENTITY_IMMUTABLE'); END;
CREATE TRIGGER attachment_legacy_quota_fence BEFORE UPDATE OF quota_size ON attachment_uploads
 WHEN NEW.quota_size IS NOT OLD.quota_size AND NOT (NEW.quota_size IS NULL AND NEW.status='READY' AND OLD.status='UPLOADING' AND OLD.write_token IS NOT NULL)
 BEGIN SELECT RAISE(ABORT,'ATTACHMENT_QUOTA_RESERVATION_IMMUTABLE'); END;
CREATE TRIGGER wallpaper_storage_identity BEFORE UPDATE OF owner_admin_user_id,object_key ON wallpaper_uploads
 WHEN NEW.owner_admin_user_id<>OLD.owner_admin_user_id OR NEW.object_key<>OLD.object_key
 BEGIN SELECT RAISE(ABORT,'WALLPAPER_STORAGE_IDENTITY_IMMUTABLE'); END;

-- Durable per-room credit allocations. Unknown historical rooms stop new allocations
-- until their authoritative Durable Object reports its retained usage.
CREATE TABLE chat_capacity_limits(id INTEGER PRIMARY KEY CHECK(id=1),bytes INTEGER NOT NULL,rows INTEGER NOT NULL);
INSERT INTO chat_capacity_limits VALUES(1,107374182400,10000000);
CREATE TABLE chat_storage_capacity(
 chat_id TEXT PRIMARY KEY REFERENCES chats(chat_id),
 allocated_bytes INTEGER NOT NULL DEFAULT 0 CHECK(allocated_bytes>=0),
 allocated_rows INTEGER NOT NULL DEFAULT 0 CHECK(allocated_rows>=0),
 reconciled INTEGER NOT NULL DEFAULT 0 CHECK(reconciled IN (0,1))
);
INSERT INTO chat_storage_capacity(chat_id) SELECT chat_id FROM chats;
CREATE TRIGGER chat_capacity_new AFTER INSERT ON chats
 BEGIN INSERT INTO chat_storage_capacity(chat_id,reconciled) VALUES(NEW.chat_id,1); END;
CREATE INDEX idx_chat_capacity_pending ON chat_storage_capacity(reconciled,chat_id);

-- A browser device has one replaceable push endpoint. Keep its newest registration.
DELETE FROM push_subscriptions WHERE subscription_id IN (
 SELECT subscription_id FROM (
  SELECT subscription_id,ROW_NUMBER() OVER(PARTITION BY device_id ORDER BY revoked_at IS NOT NULL,created_at DESC,subscription_id DESC) AS n
  FROM push_subscriptions
 ) WHERE n>1
);
CREATE UNIQUE INDEX idx_push_one_device ON push_subscriptions(device_id);
CREATE INDEX idx_push_user ON push_subscriptions(user_id);
CREATE TRIGGER push_subscription_limit BEFORE INSERT ON push_subscriptions
 WHEN NOT EXISTS(SELECT 1 FROM push_subscriptions WHERE device_id=NEW.device_id)
 BEGIN
  SELECT CASE WHEN (SELECT COUNT(*) FROM push_subscriptions WHERE user_id=NEW.user_id)>=16
    OR (SELECT COUNT(*) FROM push_subscriptions)>=50000
   THEN RAISE(ABORT,'PUSH_SUBSCRIPTION_QUOTA_EXCEEDED') END;
 END;
CREATE TABLE push_wakeups(
 subscription_id TEXT PRIMARY KEY REFERENCES push_subscriptions(subscription_id) ON DELETE CASCADE,
 requested_at INTEGER NOT NULL,
 generation INTEGER NOT NULL DEFAULT 1,
 next_attempt_at INTEGER NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0,
 lease_token TEXT,
 lease_until INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_push_wakeups_due ON push_wakeups(next_attempt_at,lease_until,requested_at);

CREATE TRIGGER attachment_usage_insert AFTER INSERT ON attachment_uploads
 BEGIN
  INSERT INTO object_storage_usage(kind,owner_id,bytes,objects,pending,records) VALUES('attachment',NEW.owner_user_id,CASE WHEN NEW.cleaned_at IS NULL THEN COALESCE(NEW.quota_size,NEW.size) ELSE 0 END,(NEW.cleaned_at IS NULL),(NEW.cleaned_at IS NULL AND NEW.status<>'COMMITTED'),1) ON CONFLICT(kind,owner_id) DO UPDATE SET bytes=bytes+excluded.bytes,objects=objects+excluded.objects,pending=pending+excluded.pending,records=records+excluded.records;
  INSERT INTO object_storage_usage(kind,owner_id,bytes,objects,pending,records) VALUES('attachment','*',CASE WHEN NEW.cleaned_at IS NULL THEN COALESCE(NEW.quota_size,NEW.size) ELSE 0 END,(NEW.cleaned_at IS NULL),(NEW.cleaned_at IS NULL AND NEW.status<>'COMMITTED'),1) ON CONFLICT(kind,owner_id) DO UPDATE SET bytes=bytes+excluded.bytes,objects=objects+excluded.objects,pending=pending+excluded.pending,records=records+excluded.records;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM object_storage_usage u JOIN storage_limits l ON l.kind=u.kind WHERE u.kind='attachment' AND ((u.owner_id=NEW.owner_user_id AND (u.bytes>l.owner_bytes OR u.objects>l.owner_objects OR u.records>l.owner_objects OR u.pending>16)) OR (u.owner_id='*' AND (u.bytes>l.global_bytes OR u.objects>l.global_objects OR u.records>l.global_objects)))) THEN RAISE(ABORT,'ATTACHMENT_QUOTA_EXCEEDED') END;
 END;

CREATE TRIGGER attachment_usage_update AFTER UPDATE ON attachment_uploads
 BEGIN
  UPDATE object_storage_usage SET bytes=bytes+((CASE WHEN NEW.cleaned_at IS NULL THEN COALESCE(NEW.quota_size,NEW.size) ELSE 0 END)-(CASE WHEN OLD.cleaned_at IS NULL THEN COALESCE(OLD.quota_size,OLD.size) ELSE 0 END)),objects=objects+(((NEW.cleaned_at IS NULL))-((OLD.cleaned_at IS NULL))),pending=pending+(((NEW.cleaned_at IS NULL AND NEW.status<>'COMMITTED'))-((OLD.cleaned_at IS NULL AND OLD.status<>'COMMITTED'))),records=records+((1)-(1)) WHERE kind='attachment' AND owner_id=NEW.owner_user_id;
  UPDATE object_storage_usage SET bytes=bytes+((CASE WHEN NEW.cleaned_at IS NULL THEN COALESCE(NEW.quota_size,NEW.size) ELSE 0 END)-(CASE WHEN OLD.cleaned_at IS NULL THEN COALESCE(OLD.quota_size,OLD.size) ELSE 0 END)),objects=objects+(((NEW.cleaned_at IS NULL))-((OLD.cleaned_at IS NULL))),pending=pending+(((NEW.cleaned_at IS NULL AND NEW.status<>'COMMITTED'))-((OLD.cleaned_at IS NULL AND OLD.status<>'COMMITTED'))),records=records+((1)-(1)) WHERE kind='attachment' AND owner_id='*';
 END;

CREATE TRIGGER attachment_usage_delete AFTER DELETE ON attachment_uploads
 BEGIN
  UPDATE object_storage_usage SET bytes=bytes+(-(CASE WHEN OLD.cleaned_at IS NULL THEN COALESCE(OLD.quota_size,OLD.size) ELSE 0 END)),objects=objects+(-((OLD.cleaned_at IS NULL))),pending=pending+(-((OLD.cleaned_at IS NULL AND OLD.status<>'COMMITTED'))),records=records+(-(1)) WHERE kind='attachment' AND owner_id=OLD.owner_user_id;
  UPDATE object_storage_usage SET bytes=bytes+(-(CASE WHEN OLD.cleaned_at IS NULL THEN COALESCE(OLD.quota_size,OLD.size) ELSE 0 END)),objects=objects+(-((OLD.cleaned_at IS NULL))),pending=pending+(-((OLD.cleaned_at IS NULL AND OLD.status<>'COMMITTED'))),records=records+(-(1)) WHERE kind='attachment' AND owner_id='*';
 END;

CREATE TRIGGER wallpaper_usage_insert AFTER INSERT ON wallpaper_uploads
 BEGIN
  INSERT INTO object_storage_usage(kind,owner_id,bytes,objects,pending,records) VALUES('wallpaper',NEW.owner_admin_user_id,CASE WHEN NEW.cleaned_at IS NULL THEN NEW.size ELSE 0 END,(NEW.cleaned_at IS NULL),0,1) ON CONFLICT(kind,owner_id) DO UPDATE SET bytes=bytes+excluded.bytes,objects=objects+excluded.objects,pending=pending+excluded.pending,records=records+excluded.records;
  INSERT INTO object_storage_usage(kind,owner_id,bytes,objects,pending,records) VALUES('wallpaper','*',CASE WHEN NEW.cleaned_at IS NULL THEN NEW.size ELSE 0 END,(NEW.cleaned_at IS NULL),0,1) ON CONFLICT(kind,owner_id) DO UPDATE SET bytes=bytes+excluded.bytes,objects=objects+excluded.objects,pending=pending+excluded.pending,records=records+excluded.records;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM object_storage_usage u JOIN storage_limits l ON l.kind=u.kind WHERE u.kind='wallpaper' AND ((u.owner_id=NEW.owner_admin_user_id AND (u.bytes>l.owner_bytes OR u.objects>l.owner_objects OR u.records>l.owner_objects*32)) OR (u.owner_id='*' AND (u.bytes>l.global_bytes OR u.objects>l.global_objects OR u.records>l.global_objects*10)))) THEN RAISE(ABORT,'WALLPAPER_QUOTA_EXCEEDED') END;
 END;

CREATE TRIGGER wallpaper_usage_update AFTER UPDATE ON wallpaper_uploads
 BEGIN
  UPDATE object_storage_usage SET bytes=bytes+((CASE WHEN NEW.cleaned_at IS NULL THEN NEW.size ELSE 0 END)-(CASE WHEN OLD.cleaned_at IS NULL THEN OLD.size ELSE 0 END)),objects=objects+(((NEW.cleaned_at IS NULL))-((OLD.cleaned_at IS NULL))),pending=pending+((0)-(0)),records=records+((1)-(1)) WHERE kind='wallpaper' AND owner_id=NEW.owner_admin_user_id;
  UPDATE object_storage_usage SET bytes=bytes+((CASE WHEN NEW.cleaned_at IS NULL THEN NEW.size ELSE 0 END)-(CASE WHEN OLD.cleaned_at IS NULL THEN OLD.size ELSE 0 END)),objects=objects+(((NEW.cleaned_at IS NULL))-((OLD.cleaned_at IS NULL))),pending=pending+((0)-(0)),records=records+((1)-(1)) WHERE kind='wallpaper' AND owner_id='*';
 END;

CREATE TRIGGER wallpaper_usage_delete AFTER DELETE ON wallpaper_uploads
 BEGIN
  UPDATE object_storage_usage SET bytes=bytes+(-(CASE WHEN OLD.cleaned_at IS NULL THEN OLD.size ELSE 0 END)),objects=objects+(-((OLD.cleaned_at IS NULL))),pending=pending+(-(0)),records=records+(-(1)) WHERE kind='wallpaper' AND owner_id=OLD.owner_admin_user_id;
  UPDATE object_storage_usage SET bytes=bytes+(-(CASE WHEN OLD.cleaned_at IS NULL THEN OLD.size ELSE 0 END)),objects=objects+(-((OLD.cleaned_at IS NULL))),pending=pending+(-(0)),records=records+(-(1)) WHERE kind='wallpaper' AND owner_id='*';
 END;
