-- Restore: one row of `auth_account_settings` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_account_settings (account_id, settings_seq, envelope, updated_at_ms)
VALUES ($1, $2, $3, $4)
