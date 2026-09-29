-- Restore: one row of `auth_identity_keys` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_identity_keys (account_id, identity_epoch, e_id, updated_at_ms)
VALUES ($1, $2, $3, $4)
