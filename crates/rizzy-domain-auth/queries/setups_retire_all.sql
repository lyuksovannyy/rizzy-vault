-- Retires every OPAQUE setup not retired yet at $1 (ADR 0047 `secrets invalidate` step 4). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_opaque_setups SET retired_at_ms = $1 WHERE retired_at_ms IS NULL
