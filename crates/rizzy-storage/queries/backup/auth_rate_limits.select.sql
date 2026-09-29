-- Backup: every row of `auth_rate_limits`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT bucket, attempts, window_started_at_ms, blocked_until_ms, expires_at_ms
FROM auth_rate_limits
ORDER BY bucket
