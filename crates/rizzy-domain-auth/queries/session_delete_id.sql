-- Ends session $2 of account $1 (ADR 0075 R3). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_sessions WHERE account_id = $1 AND session_id = $2
