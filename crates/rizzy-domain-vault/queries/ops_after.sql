-- One device's ops after a cursor, in chain order, at most $4 of them (ADR 0012 §7 "Fetch").
-- Shared.
SELECT device_seq, item_id, header, body_hash, wrap_hash, signature, body, key_wrap
FROM vault_ops WHERE vault_id = $1 AND device_id = $2 AND device_seq > $3
ORDER BY device_seq LIMIT $4
