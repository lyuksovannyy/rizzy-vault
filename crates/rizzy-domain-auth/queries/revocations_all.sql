-- Every device-revocation of account $1, by device id. Shared by both engines; every value is a bound parameter (INV-53).
SELECT device_id, revocation FROM auth_device_revocations WHERE account_id = $1 ORDER BY device_id
