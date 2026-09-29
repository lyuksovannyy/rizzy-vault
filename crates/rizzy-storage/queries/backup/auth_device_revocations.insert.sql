-- Restore: one row of `auth_device_revocations` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_device_revocations (account_id, device_id, last_accepted_device_seq, revocation, stored_at_ms)
VALUES ($1, $2, $3, $4, $5)
