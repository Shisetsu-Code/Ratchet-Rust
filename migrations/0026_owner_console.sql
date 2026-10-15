CREATE TABLE auth_commit_guards (
  assertion_id TEXT PRIMARY KEY NOT NULL,
  valid INTEGER NOT NULL CHECK(valid=1)
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
CREATE INDEX idx_owner_console_expiry ON owner_console_challenges(expires_at);
CREATE TABLE owner_console_consumptions (
  challenge_id TEXT PRIMARY KEY REFERENCES owner_console_challenges(challenge_id),
  consumed_at TEXT NOT NULL
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
-- Recheck authority inside the same D1 transaction that changes credentials.
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
