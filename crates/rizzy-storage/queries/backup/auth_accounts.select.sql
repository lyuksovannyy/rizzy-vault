-- Backup: every row of `auth_accounts`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT id, login_name, created_at_ms
FROM auth_accounts
ORDER BY id
