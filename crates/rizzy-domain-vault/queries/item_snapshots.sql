-- One item's retained snapshots as the compaction rules see them: store sequence, author,
-- clamped VV (ADR 0021 §7 input). Oldest first. Shared.
SELECT store_seq, author_device_id, clamped_vv
FROM vault_snapshots WHERE vault_id = $1 AND item_id = $2 ORDER BY store_seq
