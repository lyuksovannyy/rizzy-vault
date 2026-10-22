-- The unexpired sessions of account $1 at time $2, newest first (ADR 0075 R1), at most $3 rows. Shared by both engines; every value is a bound parameter (INV-53).
SELECT session_id, device_id, session_kind, created_at_ms, expires_at_ms FROM auth_sessions WHERE account_id = $1 AND expires_at_ms > $2 ORDER BY created_at_ms DESC, session_id ASC LIMIT $3
