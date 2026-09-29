-- Backup: every row of `auth_key_grants`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, recipient_device_id, account_key_epoch, sender_device_id, grant_record, stored_at_ms
FROM auth_key_grants
ORDER BY account_id, recipient_device_id, account_key_epoch
