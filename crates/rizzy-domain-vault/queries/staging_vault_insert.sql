-- Fixes a vault's vault_key_epoch in the staging (ADR 0092 §4 step 2). Shared.
INSERT INTO vault_rotation_staging_vaults (account_id, vault_id, vault_key_epoch) VALUES ($1, $2, $3)
