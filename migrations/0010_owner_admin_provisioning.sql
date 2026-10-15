CREATE TABLE admin_provisioning_challenges (
  challenge_id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  owner_key_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL REFERENCES users(user_id),
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_admin_provisioning_challenges_expiry
  ON admin_provisioning_challenges(expires_at);

CREATE TABLE admin_provisioning_challenge_consumptions (
  challenge_id TEXT PRIMARY KEY REFERENCES admin_provisioning_challenges(challenge_id),
  consumed_at TEXT NOT NULL
);
