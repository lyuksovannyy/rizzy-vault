-- Stores an enrolled security key (ADR 0058 point 2, ADR 0077 §4). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_webauthn_credentials (account_id, credential_id, alg, security_key, security_key_format, sign_count, label, created_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
