-- Ordered per-device send stream for interactive message pipelining.
--
-- sender_sequence is intentionally nullable for legacy/batch compatibility.
-- The new interactive streaming path always supplies it. D1 enforces strict
-- +1 progression for each (chat_id, sender_device_id), so concurrent HTTP
-- requests may overlap without allowing a later message to commit first.

ALTER TABLE messages
  ADD COLUMN sender_sequence INTEGER
  CHECK (sender_sequence IS NULL OR sender_sequence >= 1);

CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_chat_sender_sequence
  ON messages(chat_id, sender_device_id, sender_sequence)
  WHERE sender_sequence IS NOT NULL;

CREATE TABLE message_sender_streams (
  chat_id TEXT NOT NULL REFERENCES chats(chat_id),
  sender_device_id TEXT NOT NULL REFERENCES devices(device_id),
  last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  updated_at TEXT NOT NULL,
  PRIMARY KEY (chat_id, sender_device_id)
);

CREATE TRIGGER messages_sender_sequence_guard
BEFORE INSERT ON messages
WHEN NEW.sender_sequence IS NOT NULL
  AND NEW.sender_sequence != COALESCE((
    SELECT last_sequence + 1
    FROM message_sender_streams
    WHERE chat_id = NEW.chat_id
      AND sender_device_id = NEW.sender_device_id
  ), 1)
BEGIN
  SELECT RAISE(ABORT, 'SENDER_SEQUENCE_GAP');
END;

CREATE TRIGGER messages_sender_sequence_advance
AFTER INSERT ON messages
WHEN NEW.sender_sequence IS NOT NULL
BEGIN
  INSERT INTO message_sender_streams (chat_id, sender_device_id, last_sequence, updated_at)
  VALUES (NEW.chat_id, NEW.sender_device_id, NEW.sender_sequence, NEW.created_at)
  ON CONFLICT(chat_id, sender_device_id) DO UPDATE SET
    last_sequence = excluded.last_sequence,
    updated_at = excluded.updated_at;
END;
