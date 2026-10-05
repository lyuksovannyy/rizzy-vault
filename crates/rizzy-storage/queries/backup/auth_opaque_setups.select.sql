-- Backup: every row of `auth_opaque_setups`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT setup_id, ake_public_key_hash, created_at_ms, retired_at_ms
FROM auth_opaque_setups
ORDER BY setup_id
