ALTER TABLE sessions ADD COLUMN authenticator_verified_at TEXT;
UPDATE sessions
SET authenticator_verified_at = webauthn_verified_at
WHERE webauthn_verified_at IS NOT NULL;

CREATE TABLE portable_key_credentials (
  key_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX idx_portable_key_credentials_user
  ON portable_key_credentials(user_id,revoked_at);

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
CREATE INDEX idx_portable_key_challenges_expiry
  ON portable_key_challenges(expires_at,kind);

CREATE TABLE portable_key_challenge_consumptions (
  challenge_id TEXT PRIMARY KEY REFERENCES portable_key_challenges(challenge_id),
  consumed_at TEXT NOT NULL
);
