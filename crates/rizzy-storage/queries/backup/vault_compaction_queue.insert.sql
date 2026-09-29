-- Restore: one row of `vault_compaction_queue` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO vault_compaction_queue (vault_id, item_id, queued_at_ms)
VALUES ($1, $2, $3)
