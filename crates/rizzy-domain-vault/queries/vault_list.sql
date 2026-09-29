-- The vaults of one account, by id. Shared.
SELECT id FROM vault_vaults WHERE account_id = $1 ORDER BY id
