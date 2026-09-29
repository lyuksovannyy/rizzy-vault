-- Removes an item from the compaction queue, in the job's transaction. Shared.
DELETE FROM vault_compaction_queue WHERE vault_id = $1 AND item_id = $2
