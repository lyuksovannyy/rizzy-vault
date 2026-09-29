-- Replaces the account-state of account $1 only if the stored state_seq is still $5 (CRYPTO.md §10.2 compare-and-swap). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_account_states SET state_seq = $2, statement = $3, updated_at_ms = $4 WHERE account_id = $1 AND state_seq = $5
