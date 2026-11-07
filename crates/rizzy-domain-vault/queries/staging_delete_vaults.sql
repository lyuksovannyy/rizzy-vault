-- Deletes the per-vault epochs of the account's staging (ADR 0092 §4). Shared.
DELETE FROM vault_rotation_staging_vaults WHERE account_id = $1
