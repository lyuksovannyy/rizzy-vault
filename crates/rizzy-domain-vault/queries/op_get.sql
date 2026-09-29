-- The op stored at one dot, for the "Already stored" comparison (ADR 0021 §9). Shared.
SELECT header, body_hash, wrap_hash, signature, body, key_wrap
FROM vault_ops WHERE vault_id = $1 AND device_id = $2 AND device_seq = $3
