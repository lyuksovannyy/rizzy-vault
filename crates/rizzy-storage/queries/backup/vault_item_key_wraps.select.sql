-- Backup: every row of `vault_item_key_wraps`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT vault_id, item_id, item_key_id, vault_key_epoch, envelope, updated_at_ms
FROM vault_item_key_wraps
ORDER BY vault_id, item_id, item_key_id
