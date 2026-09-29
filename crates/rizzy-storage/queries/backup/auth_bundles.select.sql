-- Backup: every row of `auth_bundles`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, bundle_seq, bundle, stored_at_ms
FROM auth_bundles
ORDER BY account_id, bundle_seq
