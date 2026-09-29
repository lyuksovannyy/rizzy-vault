-- The session whose bearer token hashes to $1. Shared by both engines; every value is a bound parameter (INV-53).
SELECT session_id, account_id, device_id, session_kind, created_at_ms, expires_at_ms, request_counter_max, request_counter_window FROM auth_sessions WHERE token_hash = $1
