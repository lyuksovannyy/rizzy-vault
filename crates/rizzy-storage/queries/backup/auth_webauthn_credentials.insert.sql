-- Restore: one row of `auth_webauthn_credentials` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_webauthn_credentials (account_id, credential_id, alg, security_key, security_key_format, sign_count, label, created_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
