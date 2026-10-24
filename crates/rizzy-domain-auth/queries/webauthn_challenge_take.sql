-- Reads and deletes ceremony state $1 in one statement, so it is used at most once (ADR 0077 §2 rule 1). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_webauthn_challenges WHERE challenge_id = $1 RETURNING account_id, purpose, state_format, state, expires_at_ms
