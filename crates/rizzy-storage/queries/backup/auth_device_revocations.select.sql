-- Backup: every row of `auth_device_revocations`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, device_id, last_accepted_device_seq, revocation, stored_at_ms
FROM auth_device_revocations
ORDER BY account_id, device_id
