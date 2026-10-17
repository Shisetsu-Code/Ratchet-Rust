DELETE FROM portable_key_challenge_consumptions WHERE challenge_id IN (
  SELECT challenge_id FROM portable_key_challenges WHERE expires_at<=?1 ORDER BY expires_at,challenge_id LIMIT ?2
);
DELETE FROM portable_key_challenges WHERE challenge_id IN (
  SELECT challenge_id FROM portable_key_challenges WHERE expires_at<=?1 ORDER BY expires_at,challenge_id LIMIT ?2
);
DELETE FROM webauthn_challenge_consumptions WHERE challenge_id IN (
  SELECT challenge_id FROM webauthn_challenges WHERE expires_at<=?1 ORDER BY expires_at,challenge_id LIMIT ?2
);
DELETE FROM webauthn_challenges WHERE challenge_id IN (
  SELECT challenge_id FROM webauthn_challenges WHERE expires_at<=?1 ORDER BY expires_at,challenge_id LIMIT ?2
);
DELETE FROM admin_provisioning_challenge_consumptions WHERE challenge_id IN (
  SELECT challenge_id FROM admin_provisioning_challenges WHERE expires_at<=?1 ORDER BY expires_at,challenge_id LIMIT ?2
);
DELETE FROM admin_provisioning_challenges WHERE challenge_id IN (
  SELECT challenge_id FROM admin_provisioning_challenges WHERE expires_at<=?1 ORDER BY expires_at,challenge_id LIMIT ?2
);
DELETE FROM owner_console_consumptions WHERE challenge_id IN (
  SELECT challenge_id FROM owner_console_challenges WHERE expires_at<=?1 ORDER BY expires_at,challenge_id LIMIT ?2
);
DELETE FROM owner_console_challenges WHERE challenge_id IN (
  SELECT challenge_id FROM owner_console_challenges WHERE expires_at<=?1 ORDER BY expires_at,challenge_id LIMIT ?2
);
