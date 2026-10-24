-- Writes a security key's updated SecurityKey JSON and counter of record after an assertion (ADR 0077 §4). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_webauthn_credentials SET security_key = $3, security_key_format = $4, sign_count = $5 WHERE account_id = $1 AND credential_id = $2
