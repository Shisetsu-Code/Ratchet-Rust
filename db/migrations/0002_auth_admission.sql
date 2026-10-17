-- Additive migration: credential and challenge identities are preserved.
-- Limits are admission policy, never counters reset by a successful login.
CREATE TABLE auth_admission_policy (
  scope TEXT PRIMARY KEY,
  max_requests INTEGER NOT NULL CHECK(max_requests BETWEEN 1 AND 2000),
  max_origin_requests INTEGER NOT NULL CHECK(max_origin_requests BETWEEN 1 AND 500),
  max_pair_requests INTEGER NOT NULL CHECK(max_pair_requests BETWEEN 1 AND 100),
  max_active INTEGER NOT NULL CHECK(max_active BETWEEN 0 AND 32),
  max_origin_active INTEGER NOT NULL CHECK(max_origin_active BETWEEN 0 AND 16),
  free_principal_requests INTEGER NOT NULL CHECK(free_principal_requests BETWEEN 0 AND 100)
);
INSERT INTO auth_admission_policy VALUES
  ('password_login',120,30,15,4,2,10),
  ('password_reauth',60,30,10,4,2,100),
  ('password_write',30,30,10,4,2,100),
  ('password_proof',120,12,6,0,0,100),
  ('challenge_public',240,40,20,0,0,100),
  ('challenge_reauth',120,40,20,0,0,100);

CREATE TABLE auth_password_proofs (
  challenge_id TEXT PRIMARY KEY CHECK(length(challenge_id)=36),
  challenge TEXT NOT NULL CHECK(length(challenge)=43),
  origin_hash TEXT NOT NULL CHECK(length(origin_hash)=64),
  principal_hash TEXT NOT NULL CHECK(length(principal_hash)=64),
  difficulty INTEGER NOT NULL CHECK(difficulty BETWEEN 18 AND 22),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+120),
  consumed_at INTEGER
);
CREATE INDEX auth_password_proofs_expiry ON auth_password_proofs(expires_at);
CREATE INDEX auth_password_proofs_origin ON auth_password_proofs(origin_hash,expires_at);
CREATE INDEX auth_password_proofs_principal ON auth_password_proofs(origin_hash,principal_hash,expires_at);
CREATE TRIGGER auth_password_proofs_capacity BEFORE INSERT ON auth_password_proofs BEGIN
  SELECT CASE WHEN (SELECT COUNT(*) FROM auth_password_proofs)>=512
    OR (SELECT COUNT(*) FROM auth_password_proofs WHERE origin_hash=NEW.origin_hash AND expires_at>NEW.created_at)>=4
    THEN RAISE(ABORT,'auth_rate_limited') END;
END;

CREATE TABLE auth_admission_permits (
  permit_id TEXT PRIMARY KEY CHECK(length(permit_id)=36),
  scope TEXT NOT NULL REFERENCES auth_admission_policy(scope),
  origin_hash TEXT NOT NULL CHECK(length(origin_hash)=64),
  principal_hash TEXT NOT NULL CHECK(length(principal_hash)=64),
  issued_at INTEGER NOT NULL,
  leased_until INTEGER NOT NULL CHECK(leased_until>=issued_at AND leased_until<=issued_at+120),
  released_at INTEGER,
  proof_id TEXT
);
CREATE INDEX auth_permits_scope_time ON auth_admission_permits(scope,issued_at);
CREATE INDEX auth_permits_origin_time ON auth_admission_permits(scope,origin_hash,issued_at);
CREATE INDEX auth_permits_pair_time ON auth_admission_permits(scope,origin_hash,principal_hash,issued_at);
CREATE INDEX auth_permits_principal_time ON auth_admission_permits(scope,principal_hash,issued_at);
CREATE INDEX auth_permits_active ON auth_admission_permits(scope,leased_until) WHERE released_at IS NULL;

-- A single INSERT serializes all budgets and consumes at most one proof.
-- Count admitted requests for real AND unknown names before loading credentials.
CREATE TRIGGER auth_admission_reserve BEFORE INSERT ON auth_admission_permits BEGIN
  SELECT CASE WHEN (SELECT COUNT(*) FROM auth_admission_permits)>=10000
    OR (SELECT COUNT(*) FROM auth_admission_permits WHERE scope=NEW.scope AND issued_at>NEW.issued_at-60)>=(SELECT max_requests FROM auth_admission_policy WHERE scope=NEW.scope)
    OR (SELECT COUNT(*) FROM auth_admission_permits WHERE scope=NEW.scope AND origin_hash=NEW.origin_hash AND issued_at>NEW.issued_at-60)>=(SELECT max_origin_requests FROM auth_admission_policy WHERE scope=NEW.scope)
    OR (SELECT COUNT(*) FROM auth_admission_permits WHERE scope=NEW.scope AND origin_hash=NEW.origin_hash AND principal_hash=NEW.principal_hash AND issued_at>NEW.issued_at-60)>=(SELECT max_pair_requests FROM auth_admission_policy WHERE scope=NEW.scope)
    OR (NEW.released_at IS NULL AND (SELECT COUNT(*) FROM auth_admission_permits WHERE scope=NEW.scope AND released_at IS NULL AND leased_until>NEW.issued_at)>=(SELECT max_active FROM auth_admission_policy WHERE scope=NEW.scope))
    OR (NEW.released_at IS NULL AND (SELECT COUNT(*) FROM auth_admission_permits WHERE scope=NEW.scope AND origin_hash=NEW.origin_hash AND released_at IS NULL AND leased_until>NEW.issued_at)>=(SELECT max_origin_active FROM auth_admission_policy WHERE scope=NEW.scope))
    THEN RAISE(ABORT,'auth_rate_limited') END;
  SELECT CASE WHEN NEW.scope='password_login' AND (
    NEW.proof_id IS NOT NULL OR
    (SELECT COUNT(*) FROM auth_admission_permits WHERE scope=NEW.scope AND principal_hash=NEW.principal_hash AND issued_at>NEW.issued_at-60)>=(SELECT free_principal_requests FROM auth_admission_policy WHERE scope=NEW.scope)
  ) AND NOT EXISTS(SELECT 1 FROM auth_password_proofs WHERE challenge_id=NEW.proof_id AND origin_hash=NEW.origin_hash AND principal_hash=NEW.principal_hash AND expires_at>NEW.issued_at AND consumed_at IS NULL)
    THEN RAISE(ABORT,'auth_proof_required') END;
END;
CREATE TRIGGER auth_admission_consume_proof AFTER INSERT ON auth_admission_permits
WHEN NEW.scope='password_login' AND NEW.proof_id IS NOT NULL BEGIN
  UPDATE auth_password_proofs SET consumed_at=NEW.issued_at WHERE challenge_id=NEW.proof_id;
END;

ALTER TABLE portable_key_challenges ADD COLUMN admission_origin TEXT CHECK(admission_origin IS NULL OR length(admission_origin)=64);
ALTER TABLE webauthn_challenges ADD COLUMN admission_origin TEXT CHECK(admission_origin IS NULL OR length(admission_origin)=64);
ALTER TABLE admin_provisioning_challenges ADD COLUMN admission_origin TEXT CHECK(admission_origin IS NULL OR length(admission_origin)=64);
ALTER TABLE owner_console_challenges ADD COLUMN admission_origin TEXT CHECK(admission_origin IS NULL OR length(admission_origin)=64);
CREATE INDEX portable_challenge_origin ON portable_key_challenges(kind,admission_origin,expires_at);
CREATE INDEX webauthn_challenge_origin ON webauthn_challenges(kind,admission_origin,expires_at);
CREATE INDEX admin_challenge_origin ON admin_provisioning_challenges(admission_origin,expires_at);
CREATE INDEX owner_challenge_origin ON owner_console_challenges(admission_origin,expires_at);
CREATE TABLE auth_challenge_policy (
  kind TEXT PRIMARY KEY CHECK(kind IN ('AUTHENTICATION','REAUTHENTICATION')),
  max_pending INTEGER NOT NULL CHECK(max_pending BETWEEN 1 AND 10000),
  max_origin_pending INTEGER NOT NULL CHECK(max_origin_pending BETWEEN 1 AND 500)
);
INSERT INTO auth_challenge_policy VALUES('AUTHENTICATION',2000,40),('REAUTHENTICATION',512,40);

-- Legacy NULL-origin writers remain compatible during an additive rollout;
-- the new Worker always supplies a hashed origin and an admission permit.
-- Include expired rows in the retained-row cap. Cleanup must actually remove
-- them; a TTL value alone is not an accounting boundary.
CREATE TRIGGER portable_challenge_admission BEFORE INSERT ON portable_key_challenges
WHEN NEW.kind IN ('AUTHENTICATION','REAUTHENTICATION') BEGIN
  SELECT CASE WHEN
    (SELECT COUNT(*) FROM portable_key_challenges WHERE kind=NEW.kind)+(SELECT COUNT(*) FROM webauthn_challenges WHERE kind=NEW.kind)>=(SELECT max_pending FROM auth_challenge_policy WHERE kind=NEW.kind)
    OR (SELECT COUNT(*) FROM portable_key_challenges WHERE kind=NEW.kind AND admission_origin=NEW.admission_origin AND expires_at>NEW.created_at)+(SELECT COUNT(*) FROM webauthn_challenges WHERE kind=NEW.kind AND admission_origin=NEW.admission_origin AND expires_at>NEW.created_at)>=(SELECT max_origin_pending FROM auth_challenge_policy WHERE kind=NEW.kind)
    THEN RAISE(ABORT,'auth_challenge_capacity') END;
END;

CREATE TRIGGER bootstrap_challenge_admission BEFORE INSERT ON portable_key_challenges
WHEN NEW.kind='BOOTSTRAP' BEGIN
  SELECT CASE WHEN (SELECT COUNT(*) FROM portable_key_challenges WHERE kind='BOOTSTRAP')>=128
    OR (SELECT COUNT(*) FROM portable_key_challenges WHERE kind='BOOTSTRAP' AND admission_origin=NEW.admission_origin AND expires_at>NEW.created_at)>=16
    THEN RAISE(ABORT,'auth_challenge_capacity') END;
END;
CREATE TRIGGER admin_challenge_admission BEFORE INSERT ON admin_provisioning_challenges BEGIN
  SELECT CASE WHEN (SELECT COUNT(*) FROM admin_provisioning_challenges)>=512
    OR (SELECT COUNT(*) FROM admin_provisioning_challenges WHERE admission_origin=NEW.admission_origin AND expires_at>NEW.created_at)>=40
    THEN RAISE(ABORT,'auth_challenge_capacity') END;
END;
CREATE TRIGGER owner_challenge_admission BEFORE INSERT ON owner_console_challenges BEGIN
  SELECT CASE WHEN (SELECT COUNT(*) FROM owner_console_challenges)>=512
    OR (SELECT COUNT(*) FROM owner_console_challenges WHERE admission_origin=NEW.admission_origin AND expires_at>NEW.created_at)>=40
    THEN RAISE(ABORT,'auth_challenge_capacity') END;
END;
CREATE TRIGGER webauthn_challenge_admission BEFORE INSERT ON webauthn_challenges
WHEN NEW.kind IN ('AUTHENTICATION','REAUTHENTICATION') BEGIN
  SELECT CASE WHEN
    (SELECT COUNT(*) FROM portable_key_challenges WHERE kind=NEW.kind)+(SELECT COUNT(*) FROM webauthn_challenges WHERE kind=NEW.kind)>=(SELECT max_pending FROM auth_challenge_policy WHERE kind=NEW.kind)
    OR (SELECT COUNT(*) FROM portable_key_challenges WHERE kind=NEW.kind AND admission_origin=NEW.admission_origin AND expires_at>NEW.created_at)+(SELECT COUNT(*) FROM webauthn_challenges WHERE kind=NEW.kind AND admission_origin=NEW.admission_origin AND expires_at>NEW.created_at)>=(SELECT max_origin_pending FROM auth_challenge_policy WHERE kind=NEW.kind)
    THEN RAISE(ABORT,'auth_challenge_capacity') END;
END;

-- The old column remains for rollback compatibility, but no longer gates login.
UPDATE password_credentials SET next_allowed_at=NULL;
