-- The length of the body of the item's op at a dot, 0 when it has none, read before R1 deletes it
-- (ADR 0048 §3: compaction credits the body it deletes). Shared.
SELECT CAST(COALESCE(length(body), 0) AS BIGINT)
FROM vault_ops
WHERE vault_id = $1 AND device_id = $2 AND device_seq = $3 AND item_id = $4
