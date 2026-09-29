-- Restore: one row of `auth_credentials` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_credentials (account_id, setup_id, opaque_record, kdf_id, password_epoch, e_srv, updated_at_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7)
