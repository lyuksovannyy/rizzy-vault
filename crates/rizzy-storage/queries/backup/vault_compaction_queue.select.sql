-- Backup: every row of `vault_compaction_queue`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT vault_id, item_id, queued_at_ms
FROM vault_compaction_queue
ORDER BY vault_id, item_id
