-- Deletes the staged rows of the account's staging (ADR 0092 §4). Shared.
DELETE FROM vault_rotation_staging WHERE account_id = $1
