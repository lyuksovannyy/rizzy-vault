-- When OPAQUE setup $1 was retired, NULL while it is accepted; no row for an unknown setup (ADR 0031 point 3). Shared by both engines; every value is a bound parameter (INV-53).
SELECT retired_at_ms FROM auth_opaque_setups WHERE setup_id = $1
