CREATE TABLE account_wallpapers (
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
  owner_admin_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('PRESET','CUSTOM')),
  preset TEXT CHECK (preset IN ('default','sand','sage','sky')),
  object_key TEXT UNIQUE,
  content_type TEXT CHECK (content_type IN ('image/jpeg','image/png','image/webp','image/gif')),
  encryption_key_b64url TEXT,
  nonce_b64url TEXT,
  updated_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, owner_admin_user_id),
  CHECK (
    (kind='PRESET' AND preset IS NOT NULL AND object_key IS NULL AND content_type IS NULL
      AND encryption_key_b64url IS NULL AND nonce_b64url IS NULL)
    OR
    (kind='CUSTOM' AND preset IS NULL AND object_key IS NOT NULL AND content_type IS NOT NULL
      AND encryption_key_b64url IS NOT NULL AND nonce_b64url IS NOT NULL)
  )
);

CREATE INDEX idx_account_wallpapers_owner
  ON account_wallpapers(owner_admin_user_id,workspace_id);

WITH legacy_ranked AS (
  SELECT
    c.workspace_id,
    CASE
      WHEN creator.staff_role='OPERATOR' AND creator.created_by_user_id IS NOT NULL
        THEN creator.created_by_user_id
      ELSE c.created_by_user_id
    END AS owner_admin_user_id,
    cw.preset,
    cw.updated_by_user_id,
    cw.updated_at,
    ROW_NUMBER() OVER (
      PARTITION BY
        c.workspace_id,
        CASE
          WHEN creator.staff_role='OPERATOR' AND creator.created_by_user_id IS NOT NULL
            THEN creator.created_by_user_id
          ELSE c.created_by_user_id
        END
      ORDER BY cw.updated_at DESC,cw.chat_id DESC
    ) AS rn
  FROM chat_wallpapers cw
  JOIN chats c ON c.chat_id=cw.chat_id
  LEFT JOIN workspace_staff creator
    ON creator.workspace_id=c.workspace_id AND creator.user_id=c.created_by_user_id
)
INSERT INTO account_wallpapers
  (workspace_id,owner_admin_user_id,kind,preset,object_key,content_type,encryption_key_b64url,nonce_b64url,updated_by_user_id,updated_at)
SELECT
  workspace_id,owner_admin_user_id,'PRESET',preset,NULL,NULL,NULL,NULL,updated_by_user_id,updated_at
FROM legacy_ranked
WHERE rn=1;
