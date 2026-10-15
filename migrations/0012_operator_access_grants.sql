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

CREATE INDEX idx_operator_access_grants_target
  ON operator_access_grants(workspace_id, operator_user_id, expires_at, claimed_at, revoked_at);
CREATE INDEX idx_operator_access_grants_expiry
  ON operator_access_grants(expires_at, claimed_at, revoked_at);

-- The UNIQUE grant_id is the concurrency latch. A claim batch inserts this row
-- first; concurrent replays cannot both commit even if they observed the grant
-- as active before either writer reached D1.
CREATE TABLE operator_access_claims (
  claim_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL UNIQUE REFERENCES operator_access_grants(grant_id),
  claimed_at TEXT NOT NULL
);
