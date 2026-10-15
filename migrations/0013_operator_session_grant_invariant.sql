ALTER TABLE operator_access_claims ADD COLUMN device_id TEXT;
ALTER TABLE operator_access_claims ADD COLUMN session_id TEXT;

CREATE UNIQUE INDEX idx_operator_access_claims_session
  ON operator_access_claims(session_id)
  WHERE session_id IS NOT NULL;
CREATE INDEX idx_operator_access_claims_device
  ON operator_access_claims(device_id,claimed_at)
  WHERE device_id IS NOT NULL;

-- An identity that is exclusively an OPERATOR may only receive a new session
-- when that exact session_id + device_id pair was authorized by a one-time
-- operator access claim. Mixed identities that also hold an active ADMIN or
-- OWNER role are deliberately exempt so a migration cannot silently lock out
-- a privileged account that spans workspaces.
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
