-- The account's rotation staging (ADR 0092 §4): its fixed triple and last stage time. Shared.
SELECT rotation_id, base_state_seq, account_key_id, last_stage_at_ms
FROM vault_rotation_stagings WHERE account_id = $1
