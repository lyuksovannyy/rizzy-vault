-- Backup: every row of `storage_account_usage`, in primary-key order (ADR 0011 "Backups"; ADR 0048 §4). Shared by both engines.
SELECT account_id, bytes_used, updated_at_ms
FROM storage_account_usage
ORDER BY account_id
