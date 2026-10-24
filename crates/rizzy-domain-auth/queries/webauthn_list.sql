-- The WebAuthn credentials of account $1, oldest first (ADR 0077 §4). Shared by both engines; every value is a bound parameter (INV-53).
SELECT credential_id, alg, security_key, security_key_format, sign_count, label, created_ms FROM auth_webauthn_credentials WHERE account_id = $1 ORDER BY created_ms, credential_id
