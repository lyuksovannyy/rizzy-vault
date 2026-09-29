-- Every data_key_id a sealed TOTP row names (CRYPTO.md §5.11 startup check). Shared by both engines; every value is a bound parameter (INV-53).
SELECT DISTINCT data_key_id FROM auth_totp_credentials
