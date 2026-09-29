-- The pending ACCOUNT_KEY_DEVICE_GRANTs of recipient device $2 of account $1, lowest epoch first (CRYPTO.md §11.3 step 4.1). Shared by both engines; every value is a bound parameter (INV-53).
SELECT account_key_epoch, sender_device_id, grant_record FROM auth_key_grants WHERE account_id = $1 AND recipient_device_id = $2 ORDER BY account_key_epoch
