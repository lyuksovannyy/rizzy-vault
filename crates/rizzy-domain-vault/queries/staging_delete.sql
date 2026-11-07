-- Deletes the account's staging itself (ADR 0092 §4). Shared.
DELETE FROM vault_rotation_stagings WHERE account_id = $1
