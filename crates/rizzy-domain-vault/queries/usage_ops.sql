-- One account's op rows for the storage counter (ADR 0048 §2, §4): their number and the summed
-- lengths of header, signature, body and carried wrap; the caller adds the statement framing per
-- row. Contents are not read. Shared.
SELECT CAST(COUNT(*) AS BIGINT),
       CAST(COALESCE(SUM(length(o.header) + length(o.signature) + COALESCE(length(o.body), 0)
                         + COALESCE(length(o.key_wrap), 0)), 0) AS BIGINT)
FROM vault_ops o JOIN vault_vaults v ON v.id = o.vault_id
WHERE v.account_id = $1
