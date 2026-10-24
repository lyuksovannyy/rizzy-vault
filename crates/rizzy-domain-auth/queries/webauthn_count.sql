-- The number of WebAuthn credentials of account $1 (ADR 0058 point 3). Shared by both engines; every value is a bound parameter (INV-53).
SELECT COUNT(*) FROM auth_webauthn_credentials WHERE account_id = $1
