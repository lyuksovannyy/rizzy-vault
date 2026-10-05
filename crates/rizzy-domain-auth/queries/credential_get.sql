-- The OPAQUE record of account $1 with its setup, kdf_id, password_epoch, E_srv and the account_key_epoch of its commit (ADR 0032 §4). Shared by both engines; every value is a bound parameter (INV-53).
SELECT setup_id, opaque_record, kdf_id, password_epoch, e_srv, account_key_epoch FROM auth_credentials WHERE account_id = $1
