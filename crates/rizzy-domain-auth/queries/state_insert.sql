-- Stores the first account-state of account $1 (state_seq 1, CRYPTO.md §11.1). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_account_states (account_id, state_seq, statement, updated_at_ms) VALUES ($1, $2, $3, $4)
