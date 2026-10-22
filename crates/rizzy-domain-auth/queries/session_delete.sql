-- Ends the session whose bearer token hashes to $1 (ADR 0075 R2). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_sessions WHERE token_hash = $1
