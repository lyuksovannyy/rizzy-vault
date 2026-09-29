-- Reads and deletes the login state $1 in one statement, so it is used at most once (CRYPTO.md §5.11). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_login_states WHERE login_id = $1 RETURNING credential_identifier, data_key_id, sealed_state, expires_at_ms
