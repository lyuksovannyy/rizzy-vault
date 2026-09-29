-- Backup: every row of `auth_identity_keys`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, identity_epoch, e_id, updated_at_ms
FROM auth_identity_keys
ORDER BY account_id
