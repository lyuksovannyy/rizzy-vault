-- The highest `vault_key_epoch` among the vault's stored op and snapshot headers, all of them
-- signed statements the server verified on upload; NULL when the vault holds none. The bound of
-- a re-published self-grant's epoch (`keys.rs`). Shared.
SELECT CAST(MAX(e) AS BIGINT) FROM (
    SELECT MAX(vault_key_epoch) AS e FROM vault_ops WHERE vault_id = $1
    UNION ALL
    SELECT MAX(vault_key_epoch) AS e FROM vault_snapshots WHERE vault_id = $1
) AS t
