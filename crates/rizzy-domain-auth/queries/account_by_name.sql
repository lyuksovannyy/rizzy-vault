-- The account id of normalised login name $1. Shared by both engines; every value is a bound parameter (INV-53).
SELECT id FROM auth_accounts WHERE login_name = $1
