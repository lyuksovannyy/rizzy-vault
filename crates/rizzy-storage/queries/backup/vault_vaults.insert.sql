-- Restore: one row of `vault_vaults` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO vault_vaults (id, account_id, vault_key_epoch, next_store_seq, created_at_ms)
VALUES ($1, $2, $3, $4, $5)
