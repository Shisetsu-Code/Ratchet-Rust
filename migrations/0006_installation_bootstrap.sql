CREATE TABLE installation_bootstrap (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  completed_at TEXT NOT NULL
);

CREATE TABLE bootstrap_webauthn_challenges (
  challenge_id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  user_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  pending_device_name TEXT NOT NULL,
  pending_crypto_identity_public_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX idx_bootstrap_webauthn_challenges_expiry
  ON bootstrap_webauthn_challenges(expires_at,consumed_at);
