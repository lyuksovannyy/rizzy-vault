-- Backup: every row of `auth_webauthn_credentials`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, credential_id, alg, security_key, security_key_format, sign_count, label, created_ms
FROM auth_webauthn_credentials
ORDER BY account_id, credential_id
