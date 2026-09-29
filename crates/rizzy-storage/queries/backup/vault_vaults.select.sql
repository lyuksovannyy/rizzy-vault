-- Backup: every row of `vault_vaults`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT id, account_id, vault_key_epoch, next_store_seq, created_at_ms
FROM vault_vaults
ORDER BY id
