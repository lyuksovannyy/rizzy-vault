-- Queues an item for the `worker` compaction job (ADR 0021 §3 "Where it runs"); an item already
-- queued keeps its place. Shared.
INSERT INTO vault_compaction_queue (vault_id, item_id, queued_at_ms) VALUES ($1, $2, $3)
ON CONFLICT (vault_id, item_id) DO NOTHING
