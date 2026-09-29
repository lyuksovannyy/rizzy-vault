-- Restore: one row of `auth_recovery` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_recovery (account_id, recovery_epoch, e_rec, h_rec, updated_at_ms)
VALUES ($1, $2, $3, $4, $5)
