-- Backup: every row of `vault_device_cursors`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT vault_id, device_id, cursor, updated_at_ms
FROM vault_device_cursors
ORDER BY vault_id, device_id
