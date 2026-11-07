-- One page of a vault's wrap-set rows after a locator, in locator order, at most $4 (ADR 0092 §5,
-- `recovery/wraps`). $2 and $3 are the last row's item and item key ids; empty for the first page
-- (every stored id is 16 bytes, so it sorts after the empty one on both engines). Shared.
SELECT item_id, item_key_id, vault_key_epoch, envelope FROM vault_item_key_wraps
WHERE vault_id = $1 AND (item_id > $2 OR (item_id = $2 AND item_key_id > $3))
ORDER BY item_id, item_key_id LIMIT $4
