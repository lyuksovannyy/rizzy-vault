-- Restore: one row of `auth_account_states` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_account_states (account_id, state_seq, statement, updated_at_ms)
VALUES ($1, $2, $3, $4)
