-- The clamped VV of every retained snapshot of a vault, for the rotation cut-off (ADR 0025 §3
-- check 4: every retained snapshot's clamped VV is at most the cursor). Shared.
SELECT clamped_vv FROM vault_snapshots WHERE vault_id = $1
