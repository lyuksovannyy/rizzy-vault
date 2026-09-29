-- Adopts a newer account-state of account $1 during the reconciliation epoch (ADR 0012 §7 healing step 2, INV-59): only over a lower stored state_seq. Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_account_states SET state_seq = $2, statement = $3, updated_at_ms = $4 WHERE account_id = $1 AND state_seq < $2
