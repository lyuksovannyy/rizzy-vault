-- Backup: every row of `auth_device_certificates`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, device_id, identity_epoch, device_kind, expires_at_ms, certificate, suspended_at_ms, stored_at_ms
FROM auth_device_certificates
ORDER BY account_id, device_id
