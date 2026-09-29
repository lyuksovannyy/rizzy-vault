-- Deletes one wrap-set row the rotating client could not open (ADR 0025 §2 step 3, §3 step 5).
-- The caller requires exactly one row deleted. Shared.
DELETE FROM vault_item_key_wraps WHERE vault_id = $1 AND item_id = $2 AND item_key_id = $3
