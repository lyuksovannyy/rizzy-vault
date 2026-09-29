-- Sets a vault's current `vault_key_epoch` to the rotation's new epoch (ADR 0025 §3 step 5). The
-- only statement that moves the column after creation. Shared.
UPDATE vault_vaults SET vault_key_epoch = $2 WHERE id = $1
