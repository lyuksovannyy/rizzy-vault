-- Restore: one row of `auth_rate_limits` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_rate_limits (bucket, attempts, window_started_at_ms, blocked_until_ms, expires_at_ms)
VALUES ($1, $2, $3, $4, $5)
