-- Restore: one row of `vault_self_grants` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO vault_self_grants (vault_id, account_key_epoch, vault_key_epoch, envelope, updated_at_ms)
VALUES ($1, $2, $3, $4, $5)
