-- One vault's op rows for the storage counter (ADR 0048 §2; ADR 0081 §A5, §A9): as usage_ops.sql,
-- for one vault. Contents are not read. Shared.
SELECT CAST(COUNT(*) AS BIGINT),
       CAST(COALESCE(SUM(length(o.header) + length(o.signature) + COALESCE(length(o.body), 0)
                         + COALESCE(length(o.key_wrap), 0)), 0) AS BIGINT)
FROM vault_ops o
WHERE o.vault_id = $1
