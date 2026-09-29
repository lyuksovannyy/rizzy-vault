-- The OPAQUE record of account $1 with its setup, kdf_id, password_epoch and E_srv. Shared by both engines; every value is a bound parameter (INV-53).
SELECT setup_id, opaque_record, kdf_id, password_epoch, e_srv FROM auth_credentials WHERE account_id = $1
