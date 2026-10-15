CREATE TABLE customer_contacts (
  workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
  user_id TEXT NOT NULL REFERENCES users(user_id),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80),
  created_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id,user_id)
);
ALTER TABLE messages ADD COLUMN reply_to_message_id TEXT REFERENCES messages(message_id);
CREATE INDEX idx_messages_reply_target ON messages(reply_to_message_id,revision);
