ALTER TABLE sessions ADD COLUMN webauthn_verified_at TEXT;
ALTER TABLE passkeys ADD COLUMN webauthn_user_id TEXT;
ALTER TABLE passkeys ADD COLUMN device_type TEXT;
ALTER TABLE passkeys ADD COLUMN backed_up INTEGER;

CREATE TABLE webauthn_challenges (
  challenge_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('REGISTRATION','AUTHENTICATION','REAUTHENTICATION')),
  challenge TEXT NOT NULL,
  user_id TEXT REFERENCES users(user_id),
  invitation_id TEXT REFERENCES invitations(invitation_id),
  pending_device_id TEXT,
  pending_device_name TEXT,
  pending_crypto_identity_public_key TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_webauthn_challenges_expiry ON webauthn_challenges(expires_at,kind);

CREATE TABLE webauthn_challenge_consumptions (
  challenge_id TEXT PRIMARY KEY REFERENCES webauthn_challenges(challenge_id),
  consumed_at TEXT NOT NULL
);
