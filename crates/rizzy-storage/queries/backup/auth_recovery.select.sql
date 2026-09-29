-- Backup: every row of `auth_recovery`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, recovery_epoch, e_rec, h_rec, updated_at_ms
FROM auth_recovery
ORDER BY account_id
