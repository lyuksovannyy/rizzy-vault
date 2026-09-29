-- Stores a sealed OPAQUE login state, 60 s TTL (CRYPTO.md §5.10, §5.11). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_login_states (login_id, credential_identifier, data_key_id, sealed_state, expires_at_ms) VALUES ($1, $2, $3, $4, $5)
