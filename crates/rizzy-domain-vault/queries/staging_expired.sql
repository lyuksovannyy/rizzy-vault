-- The accounts whose staging's last stage request is older than the cut ($1), for the worker's
-- expiry (ADR 0092 §4 "Expiry"). Shared.
SELECT account_id FROM vault_rotation_stagings WHERE last_stage_at_ms < $1 ORDER BY account_id
