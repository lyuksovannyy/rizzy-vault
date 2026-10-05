-- How many OPAQUE records name each setup_id (ADR 0031 points 5, 10). Shared by both engines; every value is a bound parameter (INV-53).
SELECT setup_id, COUNT(*) FROM auth_credentials GROUP BY setup_id ORDER BY setup_id
