-- The account of pending row $1, to take its lock first (ADR 0011). Shared by both engines; every value is a bound parameter (INV-53).
SELECT account_id, expires_at_ms FROM auth_webauthn_pending WHERE pending_id = $1
