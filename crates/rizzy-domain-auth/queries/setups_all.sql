-- Every recorded OPAQUE setup with its recording and retirement times, by setup_id (ADR 0031 points 1, 5, 10). Shared by both engines; every value is a bound parameter (INV-53).
SELECT setup_id, created_at_ms, retired_at_ms FROM auth_opaque_setups ORDER BY setup_id
