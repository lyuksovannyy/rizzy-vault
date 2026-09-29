-- Backup: every row of `auth_pending_recoveries`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, recovery_epoch, opened_at_ms, available_at_ms
FROM auth_pending_recoveries
ORDER BY account_id
