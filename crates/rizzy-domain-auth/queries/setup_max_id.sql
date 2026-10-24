-- The highest recorded setup_id, retired and burned ones included, or NULL when none is recorded (ADR 0047 `secrets invalidate` step 4). Shared by both engines; every value is a bound parameter (INV-53).
SELECT MAX(setup_id) FROM auth_opaque_setups
