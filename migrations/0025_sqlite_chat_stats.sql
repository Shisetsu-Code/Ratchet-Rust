CREATE TABLE chat_storage_stats (
  chat_id TEXT PRIMARY KEY REFERENCES chats(chat_id),
  revision INTEGER NOT NULL,
  message_count INTEGER NOT NULL,
  last_message_at TEXT,
  last_sender_user_id TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_chat_storage_stats_updated ON chat_storage_stats(updated_at);
