-- Replaces a wrap-set row by one at a higher `vault_key_epoch` (CRYPTO.md §4.2). Shared.
UPDATE vault_item_key_wraps SET vault_key_epoch = $4, envelope = $5, updated_at_ms = $6
WHERE vault_id = $1 AND item_id = $2 AND item_key_id = $3 AND vault_key_epoch < $4
