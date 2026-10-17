-- Each separator delimits one runtime SQL statement (including whole triggers).
CREATE TABLE IF NOT EXISTS storage_usage(id INTEGER PRIMARY KEY CHECK(id=1),bytes INTEGER NOT NULL CHECK(bytes>=0),rows INTEGER NOT NULL CHECK(rows>=0),byte_limit INTEGER NOT NULL DEFAULT 0,row_limit INTEGER NOT NULL DEFAULT 0);
-- statement-break
INSERT INTO storage_usage(id,bytes,rows) SELECT 1,(SELECT COALESCE(SUM(128+COALESCE(length(CAST(kind AS BLOB)),0)+COALESCE(length(CAST(payload AS BLOB)),0)),0) FROM events)+(SELECT COALESCE(SUM(1024+COALESCE(length(CAST(chat_id AS BLOB)),0)+COALESCE(length(CAST(message_id AS BLOB)),0)+COALESCE(length(CAST(client_message_id AS BLOB)),0)+COALESCE(length(CAST(sender_user_id AS BLOB)),0)+COALESCE(length(CAST(sender_device_id AS BLOB)),0)+COALESCE(length(CAST(sender_display_name AS BLOB)),0)+COALESCE(length(CAST(created_at AS BLOB)),0)+COALESCE(length(CAST(mutation AS BLOB)),0)+COALESCE(length(CAST(reply_to_message_id AS BLOB)),0)+COALESCE(length(CAST(attachment_ids AS BLOB)),0)+COALESCE(length(CAST(fingerprint AS BLOB)),0)+COALESCE(length(CAST(nonce AS BLOB)),0)+COALESCE(length(CAST(ciphertext AS BLOB)),0)),0) FROM chat_messages)+(SELECT COALESCE(SUM(256+COALESCE(length(CAST(message_id AS BLOB)),0)+COALESCE(length(CAST(user_id AS BLOB)),0)+COALESCE(length(CAST(state AS BLOB)),0)),0) FROM receipts)+(SELECT COALESCE(SUM(256+COALESCE(length(CAST(user_id AS BLOB)),0)+COALESCE(length(CAST(request_id AS BLOB)),0)+COALESCE(length(CAST(payload AS BLOB)),0)+COALESCE(length(CAST(response AS BLOB)),0)),0) FROM receipt_requests),(SELECT COUNT(*) FROM events)+(SELECT COUNT(*) FROM chat_messages)+(SELECT COUNT(*) FROM receipts)+(SELECT COUNT(*) FROM receipt_requests) WHERE NOT EXISTS(SELECT 1 FROM storage_usage WHERE id=1);
-- statement-break
CREATE TRIGGER IF NOT EXISTS events_storage_insert AFTER INSERT ON events
 BEGIN
  UPDATE storage_usage SET bytes=bytes+(128+COALESCE(length(CAST(NEW.kind AS BLOB)),0)+COALESCE(length(CAST(NEW.payload AS BLOB)),0)),rows=rows+(1) WHERE id=1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM storage_usage WHERE id=1 AND (bytes>byte_limit OR rows>row_limit)) THEN RAISE(ABORT,'CHAT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS events_storage_delete AFTER DELETE ON events
 BEGIN
  UPDATE storage_usage SET bytes=bytes+(-(128+COALESCE(length(CAST(OLD.kind AS BLOB)),0)+COALESCE(length(CAST(OLD.payload AS BLOB)),0))),rows=rows+(-1) WHERE id=1;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS events_storage_update AFTER UPDATE ON events
 BEGIN
  UPDATE storage_usage SET bytes=bytes+((128+COALESCE(length(CAST(NEW.kind AS BLOB)),0)+COALESCE(length(CAST(NEW.payload AS BLOB)),0))-(128+COALESCE(length(CAST(OLD.kind AS BLOB)),0)+COALESCE(length(CAST(OLD.payload AS BLOB)),0))),rows=rows+(0) WHERE id=1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM storage_usage WHERE id=1 AND (bytes>byte_limit OR rows>row_limit)) THEN RAISE(ABORT,'CHAT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS chat_messages_storage_insert AFTER INSERT ON chat_messages
 BEGIN
  UPDATE storage_usage SET bytes=bytes+(1024+COALESCE(length(CAST(NEW.chat_id AS BLOB)),0)+COALESCE(length(CAST(NEW.message_id AS BLOB)),0)+COALESCE(length(CAST(NEW.client_message_id AS BLOB)),0)+COALESCE(length(CAST(NEW.sender_user_id AS BLOB)),0)+COALESCE(length(CAST(NEW.sender_device_id AS BLOB)),0)+COALESCE(length(CAST(NEW.sender_display_name AS BLOB)),0)+COALESCE(length(CAST(NEW.created_at AS BLOB)),0)+COALESCE(length(CAST(NEW.mutation AS BLOB)),0)+COALESCE(length(CAST(NEW.reply_to_message_id AS BLOB)),0)+COALESCE(length(CAST(NEW.attachment_ids AS BLOB)),0)+COALESCE(length(CAST(NEW.fingerprint AS BLOB)),0)+COALESCE(length(CAST(NEW.nonce AS BLOB)),0)+COALESCE(length(CAST(NEW.ciphertext AS BLOB)),0)),rows=rows+(1) WHERE id=1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM storage_usage WHERE id=1 AND (bytes>byte_limit OR rows>row_limit)) THEN RAISE(ABORT,'CHAT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS chat_messages_storage_delete AFTER DELETE ON chat_messages
 BEGIN
  UPDATE storage_usage SET bytes=bytes+(-(1024+COALESCE(length(CAST(OLD.chat_id AS BLOB)),0)+COALESCE(length(CAST(OLD.message_id AS BLOB)),0)+COALESCE(length(CAST(OLD.client_message_id AS BLOB)),0)+COALESCE(length(CAST(OLD.sender_user_id AS BLOB)),0)+COALESCE(length(CAST(OLD.sender_device_id AS BLOB)),0)+COALESCE(length(CAST(OLD.sender_display_name AS BLOB)),0)+COALESCE(length(CAST(OLD.created_at AS BLOB)),0)+COALESCE(length(CAST(OLD.mutation AS BLOB)),0)+COALESCE(length(CAST(OLD.reply_to_message_id AS BLOB)),0)+COALESCE(length(CAST(OLD.attachment_ids AS BLOB)),0)+COALESCE(length(CAST(OLD.fingerprint AS BLOB)),0)+COALESCE(length(CAST(OLD.nonce AS BLOB)),0)+COALESCE(length(CAST(OLD.ciphertext AS BLOB)),0))),rows=rows+(-1) WHERE id=1;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS chat_messages_storage_update AFTER UPDATE ON chat_messages
 BEGIN
  UPDATE storage_usage SET bytes=bytes+((1024+COALESCE(length(CAST(NEW.chat_id AS BLOB)),0)+COALESCE(length(CAST(NEW.message_id AS BLOB)),0)+COALESCE(length(CAST(NEW.client_message_id AS BLOB)),0)+COALESCE(length(CAST(NEW.sender_user_id AS BLOB)),0)+COALESCE(length(CAST(NEW.sender_device_id AS BLOB)),0)+COALESCE(length(CAST(NEW.sender_display_name AS BLOB)),0)+COALESCE(length(CAST(NEW.created_at AS BLOB)),0)+COALESCE(length(CAST(NEW.mutation AS BLOB)),0)+COALESCE(length(CAST(NEW.reply_to_message_id AS BLOB)),0)+COALESCE(length(CAST(NEW.attachment_ids AS BLOB)),0)+COALESCE(length(CAST(NEW.fingerprint AS BLOB)),0)+COALESCE(length(CAST(NEW.nonce AS BLOB)),0)+COALESCE(length(CAST(NEW.ciphertext AS BLOB)),0))-(1024+COALESCE(length(CAST(OLD.chat_id AS BLOB)),0)+COALESCE(length(CAST(OLD.message_id AS BLOB)),0)+COALESCE(length(CAST(OLD.client_message_id AS BLOB)),0)+COALESCE(length(CAST(OLD.sender_user_id AS BLOB)),0)+COALESCE(length(CAST(OLD.sender_device_id AS BLOB)),0)+COALESCE(length(CAST(OLD.sender_display_name AS BLOB)),0)+COALESCE(length(CAST(OLD.created_at AS BLOB)),0)+COALESCE(length(CAST(OLD.mutation AS BLOB)),0)+COALESCE(length(CAST(OLD.reply_to_message_id AS BLOB)),0)+COALESCE(length(CAST(OLD.attachment_ids AS BLOB)),0)+COALESCE(length(CAST(OLD.fingerprint AS BLOB)),0)+COALESCE(length(CAST(OLD.nonce AS BLOB)),0)+COALESCE(length(CAST(OLD.ciphertext AS BLOB)),0))),rows=rows+(0) WHERE id=1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM storage_usage WHERE id=1 AND (bytes>byte_limit OR rows>row_limit)) THEN RAISE(ABORT,'CHAT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS receipts_storage_insert AFTER INSERT ON receipts
 BEGIN
  UPDATE storage_usage SET bytes=bytes+(256+COALESCE(length(CAST(NEW.message_id AS BLOB)),0)+COALESCE(length(CAST(NEW.user_id AS BLOB)),0)+COALESCE(length(CAST(NEW.state AS BLOB)),0)),rows=rows+(1) WHERE id=1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM storage_usage WHERE id=1 AND (bytes>byte_limit OR rows>row_limit)) THEN RAISE(ABORT,'CHAT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS receipts_storage_delete AFTER DELETE ON receipts
 BEGIN
  UPDATE storage_usage SET bytes=bytes+(-(256+COALESCE(length(CAST(OLD.message_id AS BLOB)),0)+COALESCE(length(CAST(OLD.user_id AS BLOB)),0)+COALESCE(length(CAST(OLD.state AS BLOB)),0))),rows=rows+(-1) WHERE id=1;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS receipts_storage_update AFTER UPDATE ON receipts
 BEGIN
  UPDATE storage_usage SET bytes=bytes+((256+COALESCE(length(CAST(NEW.message_id AS BLOB)),0)+COALESCE(length(CAST(NEW.user_id AS BLOB)),0)+COALESCE(length(CAST(NEW.state AS BLOB)),0))-(256+COALESCE(length(CAST(OLD.message_id AS BLOB)),0)+COALESCE(length(CAST(OLD.user_id AS BLOB)),0)+COALESCE(length(CAST(OLD.state AS BLOB)),0))),rows=rows+(0) WHERE id=1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM storage_usage WHERE id=1 AND (bytes>byte_limit OR rows>row_limit)) THEN RAISE(ABORT,'CHAT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS receipt_requests_storage_insert AFTER INSERT ON receipt_requests
 BEGIN
  UPDATE storage_usage SET bytes=bytes+(256+COALESCE(length(CAST(NEW.user_id AS BLOB)),0)+COALESCE(length(CAST(NEW.request_id AS BLOB)),0)+COALESCE(length(CAST(NEW.payload AS BLOB)),0)+COALESCE(length(CAST(NEW.response AS BLOB)),0)),rows=rows+(1) WHERE id=1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM storage_usage WHERE id=1 AND (bytes>byte_limit OR rows>row_limit)) THEN RAISE(ABORT,'CHAT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS receipt_requests_storage_delete AFTER DELETE ON receipt_requests
 BEGIN
  UPDATE storage_usage SET bytes=bytes+(-(256+COALESCE(length(CAST(OLD.user_id AS BLOB)),0)+COALESCE(length(CAST(OLD.request_id AS BLOB)),0)+COALESCE(length(CAST(OLD.payload AS BLOB)),0)+COALESCE(length(CAST(OLD.response AS BLOB)),0))),rows=rows+(-1) WHERE id=1;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS receipt_requests_storage_update AFTER UPDATE ON receipt_requests
 BEGIN
  UPDATE storage_usage SET bytes=bytes+((256+COALESCE(length(CAST(NEW.user_id AS BLOB)),0)+COALESCE(length(CAST(NEW.request_id AS BLOB)),0)+COALESCE(length(CAST(NEW.payload AS BLOB)),0)+COALESCE(length(CAST(NEW.response AS BLOB)),0))-(256+COALESCE(length(CAST(OLD.user_id AS BLOB)),0)+COALESCE(length(CAST(OLD.request_id AS BLOB)),0)+COALESCE(length(CAST(OLD.payload AS BLOB)),0)+COALESCE(length(CAST(OLD.response AS BLOB)),0))),rows=rows+(0) WHERE id=1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM storage_usage WHERE id=1 AND (bytes>byte_limit OR rows>row_limit)) THEN RAISE(ABORT,'CHAT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TABLE IF NOT EXISTS receipt_request_usage(user_id TEXT PRIMARY KEY,bytes INTEGER NOT NULL,rows INTEGER NOT NULL);
-- statement-break
INSERT INTO receipt_request_usage(user_id,bytes,rows) SELECT user_id,SUM(256+COALESCE(length(CAST(user_id AS BLOB)),0)+COALESCE(length(CAST(request_id AS BLOB)),0)+COALESCE(length(CAST(payload AS BLOB)),0)+COALESCE(length(CAST(response AS BLOB)),0)),COUNT(*) FROM receipt_requests WHERE NOT EXISTS(SELECT 1 FROM receipt_request_usage) GROUP BY user_id;
-- statement-break
CREATE TRIGGER IF NOT EXISTS receipt_requests_owner_insert AFTER INSERT ON receipt_requests
 BEGIN
  INSERT INTO receipt_request_usage(user_id,bytes,rows) VALUES(NEW.user_id,256+COALESCE(length(CAST(NEW.user_id AS BLOB)),0)+COALESCE(length(CAST(NEW.request_id AS BLOB)),0)+COALESCE(length(CAST(NEW.payload AS BLOB)),0)+COALESCE(length(CAST(NEW.response AS BLOB)),0),1) ON CONFLICT(user_id) DO UPDATE SET bytes=bytes+excluded.bytes,rows=rows+1;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM receipt_request_usage WHERE user_id=NEW.user_id AND (bytes>16777216 OR rows>50000)) THEN RAISE(ABORT,'RECEIPT_STORAGE_QUOTA_EXCEEDED') END;
 END;
-- statement-break
CREATE TRIGGER IF NOT EXISTS receipt_requests_owner_delete AFTER DELETE ON receipt_requests
 BEGIN
  UPDATE receipt_request_usage SET bytes=bytes-(256+COALESCE(length(CAST(OLD.user_id AS BLOB)),0)+COALESCE(length(CAST(OLD.request_id AS BLOB)),0)+COALESCE(length(CAST(OLD.payload AS BLOB)),0)+COALESCE(length(CAST(OLD.response AS BLOB)),0)),rows=rows-1 WHERE user_id=OLD.user_id;
 END;
-- statement-break
