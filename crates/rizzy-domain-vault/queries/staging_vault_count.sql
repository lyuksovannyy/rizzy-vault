-- The number of rows staged for one vault (ADR 0092 §4 step 5, `staged_rows`). Shared.
SELECT CAST(COUNT(*) AS BIGINT) FROM vault_rotation_staging WHERE account_id = $1 AND vault_id = $2
