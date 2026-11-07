-- The kind, expiry and device of session $2 of account $1 (ADR 0075 R3; the device for ADR 0090 §3 code 22). Shared by both engines; every value is a bound parameter (INV-53).
SELECT session_kind, expires_at_ms, device_id FROM auth_sessions WHERE account_id = $1 AND session_id = $2
