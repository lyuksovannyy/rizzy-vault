-- Ends every session of account $1. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_sessions WHERE account_id = $1
