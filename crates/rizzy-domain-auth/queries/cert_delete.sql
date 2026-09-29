-- Deletes the certificate of device $2 of account $1: an expired kind-4 certificate that authored nothing, which no peer needs to verify anything (CRYPTO.md §10.2, §11.6 step 7). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_device_certificates WHERE account_id = $1 AND device_id = $2
