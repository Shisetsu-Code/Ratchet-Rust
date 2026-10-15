CREATE TABLE account_recovery_keys (
  recovery_key_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(user_id),
  public_key TEXT NOT NULL UNIQUE,
  created_by_device_id TEXT NOT NULL REFERENCES devices(device_id),
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  replaced_by_key_id TEXT REFERENCES account_recovery_keys(recovery_key_id),
  active_slot INTEGER CHECK (active_slot IS NULL OR active_slot = 1),
  UNIQUE(user_id, active_slot)
);
CREATE INDEX idx_account_recovery_keys_user ON account_recovery_keys(user_id, created_at DESC);
CREATE INDEX idx_account_recovery_keys_active ON account_recovery_keys(user_id, active_slot);
