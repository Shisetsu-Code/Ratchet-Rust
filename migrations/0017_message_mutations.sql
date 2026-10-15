ALTER TABLE messages ADD COLUMN mutation_target_message_id TEXT REFERENCES messages(message_id);
ALTER TABLE messages ADD COLUMN mutation_type TEXT CHECK (mutation_type IN ('EDIT','TOMBSTONE'));
CREATE INDEX idx_messages_mutation_target ON messages(mutation_target_message_id,revision);
