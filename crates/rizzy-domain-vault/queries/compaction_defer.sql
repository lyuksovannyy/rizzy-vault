-- Moves a queued item behind every other queued item after its compaction failed, so one item
-- that keeps failing never holds the head of the queue (`compact.rs`). Shared.
UPDATE vault_compaction_queue
SET queued_at_ms = (SELECT MAX(queued_at_ms) FROM vault_compaction_queue) + 1
WHERE vault_id = $1 AND item_id = $2
