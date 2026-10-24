-- One vault's snapshot rows for the storage counter (ADR 0048 §2; ADR 0081 §A5, §A9): as
-- usage_snapshots.sql, for one vault. Contents are not read. Shared.
SELECT CAST(COUNT(*) AS BIGINT),
       CAST(COALESCE(SUM(length(s.header) + length(s.signature) + length(s.envelope)
                         + COALESCE(length(s.key_wrap), 0)), 0) AS BIGINT)
FROM vault_snapshots s
WHERE s.vault_id = $1
