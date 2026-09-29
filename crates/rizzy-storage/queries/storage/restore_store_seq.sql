-- After a restore, sets each vault's store-sequence counter above the highest restored store
-- sequence ("A restore keeps the stored values and sets the counter above the restored
-- maximum", ADR 0021 §2). Shared by both engines.
UPDATE vault_vaults
SET next_store_seq = (
    SELECT MAX(s.store_seq) + 1 FROM vault_snapshots s WHERE s.vault_id = vault_vaults.id
)
WHERE next_store_seq <= (
    SELECT MAX(s.store_seq) FROM vault_snapshots s WHERE s.vault_id = vault_vaults.id
)
