-- Persist ownership so later staff changes cannot silently transfer a chat.
ALTER TABLE chats ADD COLUMN owner_admin_user_id TEXT REFERENCES users(user_id);

UPDATE chats SET owner_admin_user_id=(
  SELECT CASE WHEN s.staff_role='OPERATOR' THEN s.created_by_user_id ELSE s.user_id END
  FROM workspace_staff s
  WHERE s.workspace_id=chats.workspace_id AND s.user_id=chats.created_by_user_id
);

-- Legacy INSERT callers remain compatible; unresolved ownership fails closed.
CREATE TRIGGER chats_resolve_account_owner AFTER INSERT ON chats
BEGIN
  UPDATE chats SET owner_admin_user_id=(
    SELECT CASE WHEN s.staff_role='OPERATOR' THEN s.created_by_user_id ELSE s.user_id END
    FROM workspace_staff s
    WHERE s.workspace_id=NEW.workspace_id AND s.user_id=NEW.created_by_user_id
  ) WHERE chat_id=NEW.chat_id;
END;

CREATE TRIGGER chats_keep_account_owner BEFORE UPDATE OF owner_admin_user_id,workspace_id,created_by_user_id ON chats
WHEN (OLD.owner_admin_user_id IS NOT NULL AND NEW.owner_admin_user_id IS NOT OLD.owner_admin_user_id)
  OR NEW.workspace_id IS NOT OLD.workspace_id
  OR NEW.created_by_user_id IS NOT OLD.created_by_user_id
BEGIN
  SELECT RAISE(ABORT,'Chat account ownership is immutable');
END;

DROP VIEW active_chat_members;
CREATE VIEW active_chat_members AS
SELECT c.chat_id,wm.user_id,'ADMIN' AS participant_role,wm.created_at AS joined_at
FROM chats c
JOIN workspace_staff s ON s.workspace_id=c.workspace_id AND s.revoked_at IS NULL
  AND ((s.user_id=c.owner_admin_user_id AND s.staff_role IN ('ADMIN','OWNER'))
    OR (s.staff_role='OPERATOR' AND s.created_by_user_id=c.owner_admin_user_id))
JOIN workspace_staff owner ON owner.workspace_id=c.workspace_id
  AND owner.user_id=c.owner_admin_user_id AND owner.staff_role IN ('ADMIN','OWNER')
  AND owner.revoked_at IS NULL
JOIN users ou ON ou.user_id=owner.user_id AND ou.role='ADMIN' AND ou.status='ACTIVE'
JOIN workspace_memberships om ON om.workspace_id=c.workspace_id AND om.user_id=owner.user_id
  AND om.role='ADMIN' AND om.status='ACTIVE' AND om.revoked_at IS NULL
JOIN workspace_memberships wm ON wm.workspace_id=c.workspace_id AND wm.user_id=s.user_id
  AND wm.role='ADMIN' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL
JOIN users u ON u.user_id=wm.user_id AND u.role='ADMIN' AND u.status='ACTIVE'
UNION ALL
SELECT p.chat_id,p.user_id,'CUSTOMER' AS participant_role,p.joined_at
FROM chat_participants p
JOIN chats c ON c.chat_id=p.chat_id
JOIN workspace_memberships wm ON wm.workspace_id=c.workspace_id AND wm.user_id=p.user_id
  AND wm.role='CUSTOMER' AND wm.status='ACTIVE' AND wm.revoked_at IS NULL
JOIN users u ON u.user_id=p.user_id AND u.role='CUSTOMER' AND u.status='ACTIVE'
WHERE p.participant_role='CUSTOMER' AND p.left_at IS NULL;

CREATE INDEX idx_chats_account_owner ON chats(workspace_id,owner_admin_user_id);
