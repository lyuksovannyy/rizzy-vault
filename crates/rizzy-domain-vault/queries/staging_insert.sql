-- Opens the account's rotation staging (ADR 0092 §4 step 2). Shared.
INSERT INTO vault_rotation_stagings (account_id, rotation_id, base_state_seq, account_key_id, last_stage_at_ms)
VALUES ($1, $2, $3, $4, $5)
