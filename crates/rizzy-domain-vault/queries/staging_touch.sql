-- Sets the staging's last stage time (ADR 0092 §4 step 5). Shared.
UPDATE vault_rotation_stagings SET last_stage_at_ms = $2 WHERE account_id = $1
