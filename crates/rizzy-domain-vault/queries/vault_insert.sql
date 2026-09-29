-- A new vault (CRYPTO.md §4.4: `vault_key_epoch` 0 when the vault is created). Shared.
INSERT INTO vault_vaults (id, account_id, vault_key_epoch, next_store_seq, created_at_ms)
VALUES ($1, $2, $3, 1, $4)
