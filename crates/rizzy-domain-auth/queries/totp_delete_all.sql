-- Deletes every TOTP credential of account $1. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_totp_credentials WHERE account_id = $1
