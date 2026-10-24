-- How many OPAQUE records exist, one per account (ADR 0047 `secrets invalidate` steps 3 and 8). Shared by both engines; every value is a bound parameter (INV-53).
SELECT COUNT(*) FROM auth_credentials
