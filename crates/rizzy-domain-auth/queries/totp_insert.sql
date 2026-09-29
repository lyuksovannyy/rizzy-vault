-- Stores a sealed TOTP credential (CRYPTO.md §5.11 SERVER_TOTP_SECRET). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_totp_credentials (account_id, totp_credential_seq, data_key_id, sealed_secret, last_accepted_step, created_at_ms) VALUES ($1, $2, $3, $4, NULL, $5)
