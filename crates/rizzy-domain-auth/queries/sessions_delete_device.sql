-- Ends every session of device $2 of account $1. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_sessions WHERE account_id = $1 AND device_id = $2
