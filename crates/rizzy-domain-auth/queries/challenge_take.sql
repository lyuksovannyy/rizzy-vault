-- Reads and deletes challenge $1 in one statement, so it is answered at most once (CRYPTO.md §5.10). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_device_challenges WHERE challenge = $1 RETURNING account_id, device_id, expires_at_ms
