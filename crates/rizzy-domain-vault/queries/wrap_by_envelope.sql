-- The item key id of the wrap-set row that holds exactly this envelope, if any: a record's
-- carried wrap is served only while it is still the current row (CRYPTO.md §4.2). Shared.
SELECT item_key_id FROM vault_item_key_wraps
WHERE vault_id = $1 AND item_id = $2 AND envelope = $3 ORDER BY item_key_id LIMIT 1
