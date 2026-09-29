-- Overwrites one wrap-set row with its re-wrap under the rotation's new vault key (CRYPTO.md
-- §11.6 step 9: "the re-wrapped item keys overwrite the wrap-set rows"; ADR 0025 §3 step 5).
-- The caller requires exactly one row changed. Shared.
UPDATE vault_item_key_wraps SET vault_key_epoch = $4, envelope = $5, updated_at_ms = $6
WHERE vault_id = $1 AND item_id = $2 AND item_key_id = $3
