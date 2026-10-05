-- Retires OPAQUE setup $1 at $2, keeping an earlier retirement time (ADR 0031 point 5 step 1). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_opaque_setups SET retired_at_ms = $2 WHERE setup_id = $1 AND retired_at_ms IS NULL
