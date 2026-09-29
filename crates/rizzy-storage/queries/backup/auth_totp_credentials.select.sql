-- Backup: every row of `auth_totp_credentials`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, totp_credential_seq, data_key_id, sealed_secret, last_accepted_step, created_at_ms
FROM auth_totp_credentials
ORDER BY account_id, totp_credential_seq
