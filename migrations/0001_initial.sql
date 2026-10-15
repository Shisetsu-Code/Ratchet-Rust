PRAGMA foreign_keys = ON;

CREATE TABLE users (
  user_id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('ADMIN','CUSTOMER')),
  status TEXT NOT NULL CHECK (status IN ('INVITED','ACTIVE','SUSPENDED')),
  created_at TEXT NOT NULL,
  activated_at TEXT
);
CREATE TABLE workspaces (workspace_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE workspace_memberships (
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  role TEXT NOT NULL CHECK (role IN ('ADMIN','CUSTOMER')),
  status TEXT NOT NULL CHECK (status IN ('PENDING','ACTIVE','REVOKED')),
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (workspace_id,user_id)
);
CREATE INDEX idx_workspace_memberships_user ON workspace_memberships(user_id,status);

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
CREATE INDEX idx_devices_user_active ON devices(user_id,revoked_at,authorized_at);
CREATE TABLE device_certificates (
  certificate_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  signer_device_id TEXT REFERENCES devices(device_id),
  certificate TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
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
);
CREATE INDEX idx_passkeys_user ON passkeys(user_id);
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
);
CREATE INDEX idx_sessions_user ON sessions(user_id,revoked_at,expires_at);
CREATE INDEX idx_sessions_device ON sessions(device_id,revoked_at);

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
CREATE INDEX idx_invitations_status_expiry ON invitations(status,expires_at);

CREATE TABLE chats (
  chat_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  created_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE INDEX idx_chats_workspace ON chats(workspace_id,created_at);
CREATE TABLE chat_participants (
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  participant_role TEXT NOT NULL CHECK (participant_role IN ('ADMIN','CUSTOMER')),
  joined_at TEXT NOT NULL,
  left_at TEXT,
  PRIMARY KEY (chat_id,user_id)
);
CREATE INDEX idx_chat_participants_user ON chat_participants(user_id,left_at);
CREATE TABLE chat_revisions (
  chat_id TEXT PRIMARY KEY REFERENCES chats(chat_id),
  revision INTEGER NOT NULL DEFAULT 0,
  message_revision INTEGER NOT NULL DEFAULT 0,
  receipt_revision INTEGER NOT NULL DEFAULT 0,
  mutation_revision INTEGER NOT NULL DEFAULT 0,
  device_revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE invitation_claims (
  claim_id TEXT PRIMARY KEY,
  invitation_id TEXT NOT NULL REFERENCES invitations(invitation_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  claimed_at TEXT NOT NULL,
  UNIQUE(invitation_id,user_id)
);
CREATE INDEX idx_invitation_claims_user ON invitation_claims(user_id,claimed_at);

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
CREATE TABLE one_time_prekeys (
  prekey_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  prekey_type TEXT NOT NULL CHECK (prekey_type IN ('EC','PQ')),
  public_key TEXT NOT NULL,
  signature TEXT,
  created_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX idx_one_time_prekeys_available ON one_time_prekeys(device_id,prekey_type,consumed_at);

CREATE TABLE messages (
  message_id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  sender_user_id TEXT NOT NULL REFERENCES users(user_id),
  sender_device_id TEXT NOT NULL REFERENCES devices(device_id),
  client_message_id TEXT NOT NULL,
  protocol TEXT NOT NULL,
  protocol_version INTEGER NOT NULL,
  payload_hash TEXT NOT NULL,
  revision INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(sender_device_id,client_message_id),
  UNIQUE(chat_id,revision)
);
CREATE INDEX idx_messages_chat_revision ON messages(chat_id,revision);
CREATE TABLE message_device_envelopes (
  message_id TEXT NOT NULL REFERENCES messages(message_id),
  recipient_user_id TEXT NOT NULL REFERENCES users(user_id),
  recipient_device_id TEXT NOT NULL REFERENCES devices(device_id),
  header TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  protocol TEXT NOT NULL,
  protocol_version INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(message_id,recipient_device_id)
);
CREATE INDEX idx_message_envelopes_device ON message_device_envelopes(recipient_device_id,message_id);
CREATE TABLE message_recovery_envelopes (
  message_id TEXT NOT NULL REFERENCES messages(message_id),
  recovery_key_id TEXT NOT NULL,
  wrapped_key TEXT NOT NULL,
  archive_ciphertext TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(message_id,recovery_key_id)
);
CREATE TABLE message_mutations (
  mutation_id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES messages(message_id),
  actor_user_id TEXT NOT NULL REFERENCES users(user_id),
  mutation_type TEXT NOT NULL CHECK (mutation_type IN ('EDIT','TOMBSTONE')),
  ciphertext TEXT,
  revision INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE message_receipts (
  message_id TEXT NOT NULL REFERENCES messages(message_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 2),
  updated_at TEXT NOT NULL,
  PRIMARY KEY(message_id,user_id)
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
CREATE INDEX idx_attachment_uploads_cleanup ON attachment_uploads(status,expires_at);
CREATE TABLE attachments (
  file_id TEXT PRIMARY KEY REFERENCES attachment_uploads(file_id),
  message_id TEXT REFERENCES messages(message_id),
  encrypted_metadata TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE chat_event_outbox (
  event_id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  revision INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  created_at TEXT NOT NULL,
  delivered_at TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  UNIQUE(chat_id,revision,event_type)
);
CREATE INDEX idx_chat_event_outbox_pending ON chat_event_outbox(delivered_at,created_at);
CREATE TABLE push_subscriptions (
  subscription_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  endpoint_hash TEXT NOT NULL UNIQUE,
  subscription_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
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
CREATE INDEX idx_durable_jobs_ready ON durable_jobs(status,next_attempt_at,lease_expires_at);
