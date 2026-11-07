-- The rows staged for one vault (ADR 0092 §4), wrap NULL for a dropped row, in locator order.
-- Shared.
SELECT item_id, item_key_id, wrap FROM vault_rotation_staging
WHERE account_id = $1 AND vault_id = $2 ORDER BY item_id, item_key_id
