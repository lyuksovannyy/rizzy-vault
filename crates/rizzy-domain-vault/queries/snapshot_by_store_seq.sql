-- One retained snapshot's full record, by store sequence, to serve as a cover (ADR 0021 §4).
-- Shared.
SELECT header, envelope, wrap_hash, signature, key_wrap
FROM vault_snapshots WHERE vault_id = $1 AND item_id = $2 AND store_seq = $3
