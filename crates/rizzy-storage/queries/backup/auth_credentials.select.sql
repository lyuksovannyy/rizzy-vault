-- Backup: every row of `auth_credentials`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, setup_id, opaque_record, kdf_id, password_epoch, e_srv, updated_at_ms
FROM auth_credentials
ORDER BY account_id
