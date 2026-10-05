-- E_rec and H_rec of account $1 with the recovery_epoch stored beside H_rec and the account_key_epoch of their commit (ADR 0032 §4). Shared by both engines; every value is a bound parameter (INV-53).
SELECT recovery_epoch, e_rec, h_rec, account_key_epoch FROM auth_recovery WHERE account_id = $1
