-- Records the request-counter window of session $1 (CRYPTO.md §5.10: each counter once, window of 64). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_sessions SET request_counter_max = $2, request_counter_window = $3 WHERE token_hash = $1
