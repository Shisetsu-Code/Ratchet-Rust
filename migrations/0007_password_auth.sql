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
CREATE UNIQUE INDEX idx_password_credentials_login_name ON password_credentials(login_name);

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
CREATE INDEX idx_bootstrap_password_challenges_expiry
  ON bootstrap_password_challenges(expires_at,consumed_at);
