-- A new wrap-set row (CRYPTO.md §4.2). Shared.
INSERT INTO vault_item_key_wraps (vault_id, item_id, item_key_id, vault_key_epoch, envelope, updated_at_ms)
VALUES ($1, $2, $3, $4, $5, $6)
