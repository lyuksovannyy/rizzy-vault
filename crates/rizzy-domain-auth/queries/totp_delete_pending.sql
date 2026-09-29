-- Deletes the unconfirmed TOTP enrolments of account $1 (no accepted step yet). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_totp_credentials WHERE account_id = $1 AND last_accepted_step IS NULL
