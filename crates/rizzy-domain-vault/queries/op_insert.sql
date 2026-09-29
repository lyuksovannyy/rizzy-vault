-- Stores one verified op record (ADR 0012 §7 "Upload"); `body` is NULL for a bodiless header a
-- healing request stores (ADR 0021 §9). Shared.
INSERT INTO vault_ops (vault_id, device_id, device_seq, item_id, op_id, vault_prev_seq, hlc, item_schema_version, vault_key_epoch, header, body_hash, wrap_hash, signature, body, key_wrap, stored_at_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
