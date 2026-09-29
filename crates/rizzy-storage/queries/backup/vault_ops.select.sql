-- Backup: every row of `vault_ops`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT vault_id, device_id, device_seq, item_id, op_id, vault_prev_seq, hlc, item_schema_version, vault_key_epoch, header, body_hash, wrap_hash, signature, body, key_wrap, stored_at_ms
FROM vault_ops
ORDER BY vault_id, device_id, device_seq
