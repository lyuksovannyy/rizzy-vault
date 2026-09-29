-- Records the last accepted time step of a TOTP credential (CRYPTO.md §11.15). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_totp_credentials SET last_accepted_step = $3 WHERE account_id = $1 AND totp_credential_seq = $2
