-- Stores one verified snapshot with its clamped VV and store sequence (ADR 0021 §2). Shared.
INSERT INTO vault_snapshots (vault_id, snapshot_id, item_id, author_device_id, item_schema_version, vault_key_epoch, header, envelope, wrap_hash, signature, key_wrap, clamped_vv, store_seq, stored_at_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
