-- The wrap-set rows newer than an epoch ($2 = -1 for all), at most $3 (ADR 0012 §7 "Fetch").
-- Shared.
SELECT item_id, item_key_id, vault_key_epoch, envelope FROM vault_item_key_wraps
WHERE vault_id = $1 AND vault_key_epoch > $2 ORDER BY item_id, item_key_id LIMIT $3
