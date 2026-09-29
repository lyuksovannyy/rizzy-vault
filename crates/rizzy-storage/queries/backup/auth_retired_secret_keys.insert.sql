-- Restore: one row of `auth_retired_secret_keys` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_retired_secret_keys (account_id, retired_key_id, envelope, stored_at_ms)
VALUES ($1, $2, $3, $4)
