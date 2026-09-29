-- Backup: every row of `auth_account_states`, in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT account_id, state_seq, statement, updated_at_ms
FROM auth_account_states
ORDER BY account_id
