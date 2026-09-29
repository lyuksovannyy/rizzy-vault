-- When the current account-state of account $1 was stored, to tell a state adopted after a restore from the restored one (ADR 0012 §7). Shared by both engines; every value is a bound parameter (INV-53).
SELECT updated_at_ms FROM auth_account_states WHERE account_id = $1
