-- The vault_key_epoch a vault's first stage request fixed (ADR 0092 §4 step 2). Shared.
SELECT vault_key_epoch FROM vault_rotation_staging_vaults WHERE account_id = $1 AND vault_id = $2
