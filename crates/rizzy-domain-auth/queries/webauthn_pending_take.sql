-- Reads and deletes pending row $1 in one statement: it is used once (ADR 0058 point 3). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_webauthn_pending WHERE pending_id = $1 RETURNING account_id, expires_at_ms
