-- One wrap-set row (CRYPTO.md §4.2). Shared.
SELECT vault_key_epoch, envelope FROM vault_item_key_wraps
WHERE vault_id = $1 AND item_id = $2 AND item_key_id = $3
