-- The login name of account $1. Shared by both engines; every value is a bound parameter (INV-53).
SELECT login_name FROM auth_accounts WHERE id = $1
