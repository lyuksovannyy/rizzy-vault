-- One staged row (ADR 0092 §4 step 5), wrap NULL for a dropped row. Shared.
INSERT INTO vault_rotation_staging (account_id, rotation_id, vault_id, item_id, item_key_id, wrap)
VALUES ($1, $2, $3, $4, $5, $6)
