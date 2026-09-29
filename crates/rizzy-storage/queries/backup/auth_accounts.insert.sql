-- Restore: one row of `auth_accounts` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_accounts (id, login_name, created_at_ms)
VALUES ($1, $2, $3)
