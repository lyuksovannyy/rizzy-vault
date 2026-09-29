-- Removes E_rec and H_rec of account $1 (recovery switched off). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_recovery WHERE account_id = $1
