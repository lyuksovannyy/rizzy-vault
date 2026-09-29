-- Restore: one row of `vault_item_key_wraps` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO vault_item_key_wraps (vault_id, item_id, item_key_id, vault_key_epoch, envelope, updated_at_ms)
VALUES ($1, $2, $3, $4, $5, $6)
