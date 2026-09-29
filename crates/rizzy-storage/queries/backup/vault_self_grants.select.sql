-- Backup: every row of `vault_self_grants`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT vault_id, account_key_epoch, vault_key_epoch, envelope, updated_at_ms
FROM vault_self_grants
ORDER BY vault_id
