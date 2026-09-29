-- Deletes challenges expired at $1 (ADR 0010 §5, worker). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_device_challenges WHERE expires_at_ms <= $1
