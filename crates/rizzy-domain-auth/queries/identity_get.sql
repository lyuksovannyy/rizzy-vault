-- E_id of account $1 with its identity_epoch. Shared by both engines; every value is a bound parameter (INV-53).
SELECT identity_epoch, e_id FROM auth_identity_keys WHERE account_id = $1
