-- Fresh Ratchet Rust installation. No history import or legacy D1 message storage.
PRAGMA foreign_keys=ON;

CREATE TABLE authority_operations (
  operation_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK(status IN ('PENDING','COMMITTED','ABORTED')),
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE account_wallpapers (
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
  owner_admin_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('PRESET','CUSTOM')),
  preset TEXT CHECK (preset IN ('default','sand','sage','sky')),
  object_key TEXT UNIQUE,
  content_type TEXT CHECK (content_type IN ('image/jpeg','image/png','image/webp','image/gif')),
  encryption_key_b64url TEXT,
  nonce_b64url TEXT,
  updated_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  updated_at TEXT NOT NULL, wallpaper_id TEXT, image_nonce_b64url TEXT, ciphertext_sha256_b64url TEXT, signer_device_id TEXT, signature_b64url TEXT, key_envelopes_json TEXT,
  PRIMARY KEY (workspace_id, owner_admin_user_id),
  CHECK (
    (kind='PRESET' AND preset IS NOT NULL AND object_key IS NULL AND content_type IS NULL
      AND encryption_key_b64url IS NULL AND nonce_b64url IS NULL)
    OR
    (kind='CUSTOM' AND preset IS NULL AND object_key IS NOT NULL AND content_type IS NOT NULL
      AND encryption_key_b64url IS NOT NULL AND nonce_b64url IS NOT NULL)
  )
);

CREATE TABLE admin_provisioning_challenge_consumptions (
  challenge_id TEXT PRIMARY KEY REFERENCES admin_provisioning_challenges(challenge_id),
  consumed_at TEXT NOT NULL
);

CREATE TABLE admin_provisioning_challenges (
  challenge_id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  owner_key_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE attachment_parts (
  file_id TEXT NOT NULL REFERENCES attachment_uploads(file_id) ON DELETE CASCADE,
  part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
  etag TEXT NOT NULL,
  size INTEGER NOT NULL CHECK (size > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY(file_id,part_number)
);

CREATE TABLE attachment_uploads (
  file_id TEXT PRIMARY KEY,
  upload_id TEXT,
  object_key TEXT NOT NULL UNIQUE,
  owner_user_id TEXT NOT NULL REFERENCES users(user_id),
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  status TEXT NOT NULL CHECK (status IN ('RESERVED','UPLOADING','READY','COMMITTED','ABORTED','EXPIRED')),
  size INTEGER NOT NULL CHECK (size >= 0),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE attachments (
  file_id TEXT PRIMARY KEY REFERENCES attachment_uploads(file_id),
  message_id TEXT,
  encrypted_metadata TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE auth_commit_guards (
  assertion_id TEXT PRIMARY KEY NOT NULL,
  valid INTEGER NOT NULL CHECK(valid=1)
);

CREATE TABLE bootstrap_password_challenges (
  challenge_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  pending_device_name TEXT NOT NULL,
  pending_crypto_identity_public_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE chat_participants (
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  participant_role TEXT NOT NULL CHECK (participant_role IN ('ADMIN','CUSTOMER')),
  joined_at TEXT NOT NULL,
  left_at TEXT,
  PRIMARY KEY (chat_id,user_id)
);

CREATE TABLE chat_revisions (
  chat_id TEXT PRIMARY KEY REFERENCES chats(chat_id),
  revision INTEGER NOT NULL DEFAULT 0,
  message_revision INTEGER NOT NULL DEFAULT 0,
  receipt_revision INTEGER NOT NULL DEFAULT 0,
  mutation_revision INTEGER NOT NULL DEFAULT 0,
  device_revision INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE chat_storage_attachment_claims (
  file_id TEXT PRIMARY KEY REFERENCES attachment_uploads(file_id),
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  client_message_id TEXT NOT NULL,
  sender_device_id TEXT NOT NULL REFERENCES devices(device_id),
  fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE chat_storage_stats (
  chat_id TEXT PRIMARY KEY REFERENCES chats(chat_id),
  revision INTEGER NOT NULL,
  message_count INTEGER NOT NULL,
  last_message_at TEXT,
  last_sender_user_id TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE chat_wallpapers (
  chat_id TEXT PRIMARY KEY REFERENCES chats(chat_id) ON DELETE CASCADE,
  preset TEXT NOT NULL CHECK (preset IN ('default','sand','sage','sky')),
  updated_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  updated_at TEXT NOT NULL
);

CREATE TABLE chats (
  chat_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  created_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TEXT NOT NULL,
  closed_at TEXT
, owner_admin_user_id TEXT REFERENCES users(user_id));

CREATE TABLE customer_accounts (
  user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  created_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TEXT NOT NULL
);

CREATE TABLE customer_contacts (
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80),
  created_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id,user_id)
);

CREATE TABLE device_certificates (
  certificate_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  signer_device_id TEXT REFERENCES devices(device_id),
  certificate TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE device_prekey_bundles (
  device_id TEXT PRIMARY KEY REFERENCES devices(device_id),
  identity_public_key TEXT NOT NULL,
  signed_prekey_id TEXT NOT NULL,
  signed_prekey TEXT NOT NULL,
  signed_prekey_signature TEXT NOT NULL,
  pq_last_resort_prekey_id TEXT,
  pq_last_resort_prekey TEXT,
  pq_last_resort_signature TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE devices (
  device_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  display_name TEXT NOT NULL,
  crypto_identity_public_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  authorized_at TEXT,
  revoked_at TEXT,
  last_seen_at TEXT
);

CREATE TABLE durable_jobs (
  job_id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING','LEASED','RETRY','DONE','FAILED')),
  payload TEXT NOT NULL,
  lease_owner TEXT,
  lease_token TEXT,
  lease_expires_at TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE installation_bootstrap (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  completed_at TEXT NOT NULL
);

CREATE TABLE invitation_claims (
  claim_id TEXT PRIMARY KEY,
  invitation_id TEXT NOT NULL REFERENCES invitations(invitation_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  claimed_at TEXT NOT NULL,
  UNIQUE(invitation_id,user_id)
);

CREATE TABLE invitations (
  invitation_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('ACCESS','REFERRAL')),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  chat_id TEXT REFERENCES chats(chat_id),
  customer_user_id TEXT REFERENCES users(user_id),
  token_hash TEXT NOT NULL UNIQUE,
  created_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  expires_at TEXT,
  claimed_at TEXT,
  revoked_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE','CLAIMED','REVOKED','EXPIRED')),
  created_at TEXT NOT NULL
);

CREATE TABLE message_sender_streams (
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  sender_device_id TEXT NOT NULL REFERENCES devices(device_id),
  last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (chat_id, sender_device_id)
);

CREATE TABLE one_time_prekeys (
  prekey_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  prekey_type TEXT NOT NULL CHECK (prekey_type IN ('EC','PQ')),
  public_key TEXT NOT NULL,
  signature TEXT,
  created_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE operator_access_claims (
  claim_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL UNIQUE REFERENCES operator_access_grants(grant_id),
  claimed_at TEXT NOT NULL
, device_id TEXT, session_id TEXT);

CREATE TABLE operator_access_grants (
  grant_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  operator_user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  claimed_at TEXT,
  claimed_device_id TEXT REFERENCES devices(device_id),
  revoked_at TEXT,
  FOREIGN KEY (workspace_id, operator_user_id)
    REFERENCES workspace_staff(workspace_id, user_id)
);

CREATE TABLE owner_console_audit (
  event_id TEXT PRIMARY KEY,
  challenge_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  actor_user_id TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  target_id TEXT,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE owner_console_challenges (
  challenge_id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  owner_key_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  origin TEXT NOT NULL,
  operation_digest TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  target_id TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE owner_console_consumptions (
  challenge_id TEXT PRIMARY KEY REFERENCES owner_console_challenges(challenge_id),
  consumed_at TEXT NOT NULL
);

CREATE TABLE passkeys (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  device_id TEXT REFERENCES devices(device_id),
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
, webauthn_user_id TEXT, device_type TEXT, backed_up INTEGER);

CREATE TABLE password_credentials (
  user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  login_name TEXT NOT NULL UNIQUE,
  algorithm TEXT NOT NULL CHECK (algorithm = 'PBKDF2-SHA256'),
  iterations INTEGER NOT NULL CHECK (iterations BETWEEN 100000 AND 5000000),
  salt TEXT NOT NULL,
  verifier TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  next_allowed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE portable_key_challenge_consumptions (
  challenge_id TEXT PRIMARY KEY REFERENCES portable_key_challenges(challenge_id),
  consumed_at TEXT NOT NULL
);

CREATE TABLE portable_key_challenges (
  challenge_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('BOOTSTRAP','AUTHENTICATION','REAUTHENTICATION')),
  challenge TEXT NOT NULL,
  key_id TEXT NOT NULL,
  public_key TEXT,
  user_id TEXT,
  workspace_id TEXT,
  pending_device_id TEXT,
  pending_device_name TEXT,
  pending_crypto_identity_public_key TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE portable_key_credentials (
  key_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE TABLE push_subscriptions (
  subscription_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  endpoint_hash TEXT NOT NULL UNIQUE,
  subscription_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  ip_hash TEXT,
  user_agent_hash TEXT
, webauthn_verified_at TEXT, authenticator_verified_at TEXT);

CREATE TABLE users (
  user_id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('ADMIN','CUSTOMER')),
  status TEXT NOT NULL CHECK (status IN ('INVITED','ACTIVE','SUSPENDED')),
  created_at TEXT NOT NULL,
  activated_at TEXT
);

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

CREATE TABLE webauthn_challenge_consumptions (
  challenge_id TEXT PRIMARY KEY REFERENCES webauthn_challenges(challenge_id),
  consumed_at TEXT NOT NULL
);

CREATE TABLE webauthn_challenges (
  challenge_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('REGISTRATION','AUTHENTICATION','REAUTHENTICATION')),
  challenge TEXT NOT NULL,
  user_id TEXT REFERENCES users(user_id),
  invitation_id TEXT REFERENCES invitations(invitation_id),
  pending_device_id TEXT,
  pending_device_name TEXT,
  pending_crypto_identity_public_key TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE workspace_audit_events (
  event_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  actor_user_id TEXT NOT NULL REFERENCES users(user_id),
  subject_user_id TEXT REFERENCES users(user_id),
  event_type TEXT NOT NULL CHECK (event_type IN ('OPERATOR_CREATED','OPERATOR_REVOKED')),
  created_at TEXT NOT NULL
);

CREATE TABLE workspace_memberships (
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  role TEXT NOT NULL CHECK (role IN ('ADMIN','CUSTOMER')),
  status TEXT NOT NULL CHECK (status IN ('PENDING','ACTIVE','REVOKED')),
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (workspace_id,user_id)
);

CREATE TABLE workspace_staff (
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  staff_role TEXT NOT NULL CHECK (staff_role IN ('OWNER','ADMIN','OPERATOR')),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80),
  created_by_user_id TEXT REFERENCES users(user_id),
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (workspace_id,user_id)
);

CREATE TABLE workspaces (workspace_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);

CREATE UNIQUE INDEX idx_account_wallpapers_id
  ON account_wallpapers(wallpaper_id)
  WHERE wallpaper_id IS NOT NULL;

CREATE INDEX idx_account_wallpapers_owner
  ON account_wallpapers(owner_admin_user_id,workspace_id);

CREATE INDEX idx_admin_provisioning_challenges_expiry
  ON admin_provisioning_challenges(expires_at);

CREATE INDEX idx_attachment_uploads_cleanup ON attachment_uploads(status,expires_at);

CREATE INDEX idx_attachment_uploads_owner_active
ON attachment_uploads(owner_user_id,status,expires_at);

CREATE INDEX idx_bootstrap_password_challenges_expiry
  ON bootstrap_password_challenges(expires_at,consumed_at);

CREATE INDEX idx_chat_participants_user ON chat_participants(user_id,left_at);

CREATE INDEX idx_chat_storage_stats_updated ON chat_storage_stats(updated_at);

CREATE INDEX idx_chats_account_owner ON chats(workspace_id,owner_admin_user_id);

CREATE INDEX idx_chats_workspace ON chats(workspace_id,created_at);

CREATE INDEX idx_devices_user_active ON devices(user_id,revoked_at,authorized_at);

CREATE INDEX idx_durable_jobs_ready ON durable_jobs(status,next_attempt_at,lease_expires_at);

CREATE INDEX idx_invitation_claims_chat
  ON invitation_claims(chat_id,claimed_at);

CREATE INDEX idx_invitation_claims_user ON invitation_claims(user_id,claimed_at);

CREATE INDEX idx_invitations_chat
  ON invitations(chat_id,created_at)
  WHERE chat_id IS NOT NULL;

CREATE INDEX idx_invitations_status_expiry ON invitations(status,expires_at);

CREATE INDEX idx_one_time_prekeys_available ON one_time_prekeys(device_id,prekey_type,consumed_at);

CREATE INDEX idx_operator_access_claims_device
  ON operator_access_claims(device_id,claimed_at)
  WHERE device_id IS NOT NULL;

CREATE UNIQUE INDEX idx_operator_access_claims_session
  ON operator_access_claims(session_id)
  WHERE session_id IS NOT NULL;

CREATE INDEX idx_operator_access_grants_expiry
  ON operator_access_grants(expires_at, claimed_at, revoked_at);

CREATE INDEX idx_operator_access_grants_target
  ON operator_access_grants(workspace_id, operator_user_id, expires_at, claimed_at, revoked_at);

CREATE INDEX idx_owner_console_expiry ON owner_console_challenges(expires_at);

CREATE INDEX idx_passkeys_user ON passkeys(user_id);

CREATE UNIQUE INDEX idx_password_credentials_login_name ON password_credentials(login_name);

CREATE INDEX idx_portable_key_challenges_expiry
  ON portable_key_challenges(expires_at,kind);

CREATE INDEX idx_portable_key_credentials_user
  ON portable_key_credentials(user_id,revoked_at);

CREATE INDEX idx_sessions_device ON sessions(device_id,revoked_at);

CREATE INDEX idx_sessions_user ON sessions(user_id,revoked_at,expires_at);

CREATE INDEX idx_sqlite_attachment_message ON chat_storage_attachment_claims(chat_id,client_message_id,sender_device_id);

CREATE INDEX idx_wallpaper_uploads_cleanup ON wallpaper_uploads(state,expires_at);

CREATE INDEX idx_webauthn_challenges_expiry ON webauthn_challenges(expires_at,kind);

CREATE INDEX idx_workspace_audit_events_workspace
  ON workspace_audit_events(workspace_id,created_at DESC,event_id DESC);

CREATE INDEX idx_workspace_memberships_user ON workspace_memberships(user_id,status);

CREATE INDEX idx_workspace_staff_active
  ON workspace_staff(workspace_id,revoked_at,staff_role,user_id);

CREATE VIEW active_chat_members AS
SELECT c.chat_id,wm.user_id,'ADMIN' AS participant_role,wm.created_at AS joined_at
FROM chats c
JOIN workspace_staff s ON s.workspace_id=c.workspace_id AND s.revoked_at IS NULL
  AND ((s.user_id=c.owner_admin_user_id AND s.staff_role IN ('ADMIN','OWNER'))
    OR (s.staff_role='OPERATOR' AND s.created_by_user_id=c.owner_admin_user_id))
JOIN workspace_staff owner ON owner.workspace_id=c.workspace_id
  AND owner.user_id=c.owner_admin_user_id AND owner.staff_role IN ('ADMIN','OWNER')
  AND owner.revoked_at IS NULL
JOIN users ou ON ou.user_id=owner.user_id AND ou.role='ADMIN' AND ou.status='ACTIVE'
JOIN workspace_memberships om ON om.workspace_id=c.workspace_id AND om.user_id=owner.user_id
  AND om.role='ADMIN' AND om.status='ACTIVE' AND om.revoked_at IS NULL
JOIN workspace_memberships wm ON wm.workspace_id=c.workspace_id AND wm.user_id=s.user_id
  AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL
JOIN users u ON u.user_id=wm.user_id AND u.role='ADMIN' AND u.status='ACTIVE'
UNION ALL
SELECT p.chat_id,p.user_id,'CUSTOMER' AS participant_role,p.joined_at
FROM chat_participants p
JOIN chats c ON c.chat_id=p.chat_id
JOIN workspace_memberships wm ON wm.workspace_id=c.workspace_id AND wm.user_id=p.user_id
  AND wm.role='CUSTOMER' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL
JOIN users u ON u.user_id=p.user_id AND u.role='CUSTOMER' AND u.status='ACTIVE'
WHERE p.participant_role='CUSTOMER' AND p.left_at IS NULL;

CREATE TRIGGER chats_keep_account_owner BEFORE UPDATE OF owner_admin_user_id,workspace_id,created_by_user_id ON chats
WHEN (OLD.owner_admin_user_id IS NOT NULL AND NEW.owner_admin_user_id IS NOT OLD.owner_admin_user_id)
  OR NEW.workspace_id IS NOT OLD.workspace_id
  OR NEW.created_by_user_id IS NOT OLD.created_by_user_id
BEGIN
  SELECT RAISE(ABORT,'Chat account ownership is immutable');
END;

CREATE TRIGGER chats_resolve_account_owner AFTER INSERT ON chats
BEGIN
  UPDATE chats SET owner_admin_user_id=(
    SELECT CASE WHEN s.staff_role='OPERATOR' THEN s.created_by_user_id ELSE s.user_id END
    FROM workspace_staff s
    WHERE s.workspace_id=NEW.workspace_id AND s.user_id=NEW.created_by_user_id
  ) WHERE chat_id=NEW.chat_id;
END;

CREATE TRIGGER enforce_operator_link_only_session_insert
BEFORE INSERT ON sessions
WHEN EXISTS (
  SELECT 1
  FROM workspace_staff ws
  JOIN workspace_memberships wm
    ON wm.workspace_id=ws.workspace_id AND wm.user_id=ws.user_id
   AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL
  JOIN users u
    ON u.user_id=ws.user_id AND u.role='ADMIN' AND u.status='ACTIVE'
  WHERE ws.user_id=NEW.user_id
    AND ws.staff_role='OPERATOR'
    AND ws.revoked_at IS NULL
)
AND NOT EXISTS (
  SELECT 1
  FROM workspace_staff ws
  JOIN workspace_memberships wm
    ON wm.workspace_id=ws.workspace_id AND wm.user_id=ws.user_id
   AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL
  JOIN users u
    ON u.user_id=ws.user_id AND u.role='ADMIN' AND u.status='ACTIVE'
  WHERE ws.user_id=NEW.user_id
    AND ws.staff_role IN ('OWNER','ADMIN')
    AND ws.revoked_at IS NULL
)
AND NOT EXISTS (
  SELECT 1
  FROM operator_access_claims c
  JOIN operator_access_grants g ON g.grant_id=c.grant_id
  WHERE g.operator_user_id=NEW.user_id
    AND c.device_id=NEW.device_id
    AND c.session_id=NEW.session_id
)
BEGIN
  SELECT RAISE(ABORT, 'OPERATOR_LINK_GRANT_REQUIRED');
END;

CREATE TRIGGER owner_console_consume_authority BEFORE INSERT ON owner_console_consumptions
WHEN NOT EXISTS (
    SELECT 1 FROM owner_console_challenges c
    JOIN users u ON u.user_id=c.owner_user_id AND u.role='ADMIN' AND u.status='ACTIVE'
    JOIN workspace_memberships wm ON wm.workspace_id=c.workspace_id AND wm.user_id=u.user_id
      AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL
    JOIN workspace_staff ws ON ws.workspace_id=c.workspace_id AND ws.user_id=u.user_id AND ws.staff_role='OWNER' AND ws.revoked_at IS NULL
    JOIN portable_key_credentials pk ON pk.key_id=c.owner_key_id AND pk.user_id=u.user_id AND pk.revoked_at IS NULL
    WHERE c.challenge_id=NEW.challenge_id AND c.expires_at>NEW.consumed_at
)
BEGIN
  SELECT RAISE(ABORT,'OWNER_CONSOLE_AUTHORITY_CHANGED');
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

CREATE TRIGGER wallpaper_retire_delete AFTER DELETE ON account_wallpapers
BEGIN
  UPDATE wallpaper_uploads SET state='RETIRED' WHERE object_key=OLD.object_key;
END;
