ALTER TABLE account_recovery_keys ADD COLUMN attestation_json TEXT;
ALTER TABLE account_recovery_keys ADD COLUMN generation INTEGER CHECK (generation IS NULL OR generation > 0);
CREATE UNIQUE INDEX idx_recovery_user_generation ON account_recovery_keys(user_id,generation)
  WHERE generation IS NOT NULL;
