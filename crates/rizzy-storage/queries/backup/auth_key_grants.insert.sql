-- Restore: one row of `auth_key_grants` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_key_grants (account_id, recipient_device_id, account_key_epoch, sender_device_id, grant_record, stored_at_ms)
VALUES ($1, $2, $3, $4, $5, $6)
