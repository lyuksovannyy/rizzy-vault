-- Removes one security key of account $1. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_webauthn_credentials WHERE account_id = $1 AND credential_id = $2
