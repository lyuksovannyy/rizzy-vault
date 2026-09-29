-- Backup: every row of `auth_retired_secret_keys`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, retired_key_id, envelope, stored_at_ms
FROM auth_retired_secret_keys
ORDER BY account_id, retired_key_id
