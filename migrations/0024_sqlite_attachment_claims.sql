CREATE TABLE chat_storage_attachment_claims (
  file_id TEXT PRIMARY KEY REFERENCES attachment_uploads(file_id),
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  client_message_id TEXT NOT NULL,
  sender_device_id TEXT NOT NULL REFERENCES devices(device_id),
  fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_sqlite_attachment_message ON chat_storage_attachment_claims(chat_id,client_message_id,sender_device_id);
