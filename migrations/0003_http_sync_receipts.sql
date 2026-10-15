ALTER TABLE message_receipts ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_message_receipts_revision ON message_receipts(revision,message_id);
