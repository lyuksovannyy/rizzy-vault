-- Restore: one row of `auth_pending_recoveries` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_pending_recoveries (account_id, recovery_epoch, opened_at_ms, available_at_ms)
VALUES ($1, $2, $3, $4)
