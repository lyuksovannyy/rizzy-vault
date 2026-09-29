-- Deletes every TOTP credential of account $1 except enrolment $2. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_totp_credentials WHERE account_id = $1 AND totp_credential_seq <> $2
