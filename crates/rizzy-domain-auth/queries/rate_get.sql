-- The counters of rate-limit bucket $1 (ADR 0010 §5). Shared by both engines; every value is a bound parameter (INV-53).
SELECT attempts, window_started_at_ms, blocked_until_ms FROM auth_rate_limits WHERE bucket = $1
