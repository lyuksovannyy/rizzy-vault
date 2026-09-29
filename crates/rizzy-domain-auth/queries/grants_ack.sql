-- Deletes the grants of recipient device $2 of account $1 up to epoch $3 (CRYPTO.md §10.1 acknowledgement). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_key_grants WHERE account_id = $1 AND recipient_device_id = $2 AND account_key_epoch <= $3
