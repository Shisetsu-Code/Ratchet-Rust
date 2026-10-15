CREATE TABLE customer_accounts (
  user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  created_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  created_at TEXT NOT NULL
);

CREATE TABLE chat_wallpapers (
  chat_id TEXT PRIMARY KEY REFERENCES chats(chat_id) ON DELETE CASCADE,
  preset TEXT NOT NULL CHECK (preset IN ('default','sand','sage','sky')),
  updated_by_user_id TEXT NOT NULL REFERENCES users(user_id),
  updated_at TEXT NOT NULL
);

-- Existing password-backed customers were already converted accounts.
INSERT INTO customer_accounts (user_id, created_by_user_id, created_at)
SELECT pc.user_id, c.created_by_user_id, pc.created_at
FROM password_credentials pc
JOIN chat_participants cp ON cp.user_id=pc.user_id AND cp.participant_role='CUSTOMER'
JOIN chats c ON c.chat_id=cp.chat_id
GROUP BY pc.user_id;
