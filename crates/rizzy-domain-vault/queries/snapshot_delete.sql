-- R3: drops one retained snapshot (ADR 0021 §3). Shared.
DELETE FROM vault_snapshots WHERE vault_id = $1 AND item_id = $2 AND store_seq = $3
