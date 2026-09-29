-- The current ACCOUNT_SETTINGS envelope of account $1. Shared by both engines; every value is a bound parameter (INV-53).
SELECT settings_seq, envelope FROM auth_account_settings WHERE account_id = $1
