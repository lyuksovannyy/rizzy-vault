-- The TOTP credentials of account $1, oldest enrolment first. Shared by both engines; every value is a bound parameter (INV-53).
SELECT totp_credential_seq, data_key_id, sealed_secret, last_accepted_step FROM auth_totp_credentials WHERE account_id = $1 ORDER BY totp_credential_seq
