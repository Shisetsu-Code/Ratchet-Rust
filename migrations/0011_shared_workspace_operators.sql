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

CREATE INDEX idx_workspace_staff_active
  ON workspace_staff(workspace_id,revoked_at,staff_role,user_id);

INSERT INTO workspace_staff
  (workspace_id,user_id,staff_role,display_name,created_by_user_id,created_at)
SELECT ib.workspace_id,ib.user_id,'OWNER',COALESCE(pc.login_name,'Owner'),NULL,ib.completed_at
FROM installation_bootstrap ib
LEFT JOIN password_credentials pc ON pc.user_id=ib.user_id;

INSERT INTO workspace_staff
  (workspace_id,user_id,staff_role,display_name,created_by_user_id,created_at)
SELECT wm.workspace_id,wm.user_id,'ADMIN',COALESCE(pc.login_name,'Administrador'),ib.user_id,wm.created_at
FROM workspace_memberships wm
JOIN users u ON u.user_id=wm.user_id AND u.role='ADMIN'
LEFT JOIN password_credentials pc ON pc.user_id=wm.user_id
LEFT JOIN installation_bootstrap ib ON ib.workspace_id=wm.workspace_id
WHERE NOT EXISTS (
  SELECT 1 FROM workspace_staff ws
  WHERE ws.workspace_id=wm.workspace_id AND ws.user_id=wm.user_id
);

CREATE TABLE workspace_audit_events (
  event_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  actor_user_id TEXT NOT NULL REFERENCES users(user_id),
  subject_user_id TEXT REFERENCES users(user_id),
  event_type TEXT NOT NULL CHECK (event_type IN ('OPERATOR_CREATED','OPERATOR_REVOKED')),
  created_at TEXT NOT NULL
);

CREATE INDEX idx_workspace_audit_events_workspace
  ON workspace_audit_events(workspace_id,created_at DESC,event_id DESC);

-- Staff membership is derived from the workspace, while customers remain
-- explicit one-to-one participants. This view is the single authorization and
-- recipient-set source for shared conversations.
CREATE VIEW active_chat_members AS
SELECT
  c.chat_id AS chat_id,
  wm.user_id AS user_id,
  'ADMIN' AS participant_role,
  wm.created_at AS joined_at
FROM chats c
JOIN workspace_memberships wm
  ON wm.workspace_id=c.workspace_id
 AND wm.role='ADMIN'
 AND wm.status='ACTIVE'
 AND wm.revoked_at IS NULL
JOIN users u ON u.user_id=wm.user_id AND u.role='ADMIN' AND u.status='ACTIVE'
UNION ALL
SELECT
  p.chat_id AS chat_id,
  p.user_id AS user_id,
  'CUSTOMER' AS participant_role,
  p.joined_at AS joined_at
FROM chat_participants p
JOIN chats c ON c.chat_id=p.chat_id
JOIN workspace_memberships wm
  ON wm.workspace_id=c.workspace_id
 AND wm.user_id=p.user_id
 AND wm.role='CUSTOMER'
 AND wm.status='ACTIVE'
 AND wm.revoked_at IS NULL
JOIN users u ON u.user_id=p.user_id AND u.role='CUSTOMER' AND u.status='ACTIVE'
WHERE p.participant_role='CUSTOMER' AND p.left_at IS NULL;
