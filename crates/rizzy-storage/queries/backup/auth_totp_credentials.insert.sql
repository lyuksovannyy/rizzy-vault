-- Restore: one row of `auth_totp_credentials` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_totp_credentials (account_id, totp_credential_seq, data_key_id, sealed_secret, last_accepted_step, created_at_ms)
VALUES ($1, $2, $3, $4, $5, $6)
