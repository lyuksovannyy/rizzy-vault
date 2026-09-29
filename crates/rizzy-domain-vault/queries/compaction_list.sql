-- The oldest queued items, at most $1 of them. Shared.
SELECT vault_id, item_id FROM vault_compaction_queue ORDER BY queued_at_ms, vault_id, item_id LIMIT $1
