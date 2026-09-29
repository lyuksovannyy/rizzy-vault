-- One item's op dots, each with a body flag (1 held, 0 bodiless), for the compaction job
-- (ADR 0021 §7 input). Bodies are not read. Shared.
SELECT device_id, device_seq, CAST(CASE WHEN body IS NULL THEN 0 ELSE 1 END AS BIGINT)
FROM vault_ops WHERE vault_id = $1 AND item_id = $2
