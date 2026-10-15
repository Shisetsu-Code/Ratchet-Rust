CREATE TABLE attachment_parts (
  file_id TEXT NOT NULL REFERENCES attachment_uploads(file_id) ON DELETE CASCADE,
  part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
  etag TEXT NOT NULL,
  size INTEGER NOT NULL CHECK (size > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY(file_id,part_number)
);

CREATE TABLE message_attachment_claims (
  file_id TEXT PRIMARY KEY REFERENCES attachment_uploads(file_id),
  message_id TEXT NOT NULL REFERENCES messages(message_id),
  created_at TEXT NOT NULL
);
CREATE INDEX idx_message_attachment_claims_message ON message_attachment_claims(message_id);

-- Attachment claim eligibility is enforced by createMessage() immediately before
-- the transactional D1 batch. The batch atomically inserts the claim, marks the
-- upload COMMITTED, links the attachment, and commits the message. Keeping this
-- invariant in the application transaction avoids a multi-statement CREATE TRIGGER
-- here, which is not reliably accepted by the remote D1 migration execution path.
