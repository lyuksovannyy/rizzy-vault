-- Restore: one row of `auth_device_certificates` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_device_certificates (account_id, device_id, identity_epoch, device_kind, expires_at_ms, certificate, suspended_at_ms, stored_at_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
