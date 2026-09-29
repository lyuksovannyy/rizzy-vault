-- Backup: every row of `auth_account_settings`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, settings_seq, envelope, updated_at_ms
FROM auth_account_settings
ORDER BY account_id
