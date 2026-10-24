-- The vaults of one account with their kinds, by id (ADR 0081 §A3, §A11). Shared.
SELECT id, kind FROM vault_vaults WHERE account_id = $1 ORDER BY id
