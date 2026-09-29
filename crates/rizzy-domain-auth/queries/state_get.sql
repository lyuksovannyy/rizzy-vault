-- The current signed account-state of account $1. Shared by both engines; every value is a bound parameter (INV-53).
SELECT state_seq, statement FROM auth_account_states WHERE account_id = $1
