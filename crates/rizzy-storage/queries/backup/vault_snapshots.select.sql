-- Backup: every row of `vault_snapshots`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT vault_id, snapshot_id, item_id, author_device_id, item_schema_version, vault_key_epoch, header, envelope, wrap_hash, signature, key_wrap, clamped_vv, store_seq, stored_at_ms
FROM vault_snapshots
ORDER BY vault_id, snapshot_id
