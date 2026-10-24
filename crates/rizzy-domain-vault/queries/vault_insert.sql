-- A new vault (CRYPTO.md §4.4: `vault_key_epoch` 0 when the vault is created) of a kind (ADR 0081
-- §A10: 1 the Personal vault signup creates, 2 an owned vault `vault_create` adds). Shared.
INSERT INTO vault_vaults (id, account_id, vault_key_epoch, next_store_seq, created_at_ms, kind)
VALUES ($1, $2, $3, 1, $4, $5)
