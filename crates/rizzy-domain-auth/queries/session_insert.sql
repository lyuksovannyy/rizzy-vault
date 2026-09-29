-- Stores a new session: SHA-256 of its bearer token only (CRYPTO.md §5.10, INV-8). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_sessions (token_hash, session_id, account_id, device_id, session_kind, created_at_ms, expires_at_ms, request_counter_max, request_counter_window) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, 0)
