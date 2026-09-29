-- The snapshot stored under one `snapshot_id`, for the "Already stored" comparison (ADR 0021
-- §9). Shared.
SELECT header, envelope, wrap_hash, signature, key_wrap
FROM vault_snapshots WHERE vault_id = $1 AND snapshot_id = $2
