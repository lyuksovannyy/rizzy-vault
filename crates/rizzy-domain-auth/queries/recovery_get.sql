-- E_rec and H_rec of account $1 with the recovery_epoch stored beside H_rec. Shared by both engines; every value is a bound parameter (INV-53).
SELECT recovery_epoch, e_rec, h_rec FROM auth_recovery WHERE account_id = $1
