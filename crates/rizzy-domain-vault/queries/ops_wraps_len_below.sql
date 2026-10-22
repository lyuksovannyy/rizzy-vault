-- The summed length of the carried wraps of one vault's ops below an epoch, read before a
-- rotation or healing step 3b clears them, so the storage counter is credited (ADR 0048 §2).
-- Shared.
SELECT CAST(COALESCE(SUM(length(key_wrap)), 0) AS BIGINT)
FROM vault_ops WHERE vault_id = $1 AND vault_key_epoch < $2 AND key_wrap IS NOT NULL
