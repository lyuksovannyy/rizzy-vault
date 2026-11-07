-- One vault's wrap-set rows (CRYPTO.md §4.2) for the write-time cap (ADR 0092 §2 check 1).
-- Contents are not read. Shared.
SELECT CAST(COUNT(*) AS BIGINT)
FROM vault_item_key_wraps w
WHERE w.vault_id = $1
