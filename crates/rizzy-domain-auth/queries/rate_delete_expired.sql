-- Deletes rate-limit buckets expired at $1 (ADR 0010 §5, worker). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_rate_limits WHERE expires_at_ms <= $1
