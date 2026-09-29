-- Deletes login states expired at $1 (ADR 0010 §5, worker). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_login_states WHERE expires_at_ms <= $1
