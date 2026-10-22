-- One account's snapshot rows for the storage counter (ADR 0048 §2, §4): their number and the
-- summed lengths of header, signature, envelope and carried wrap; the caller adds the statement
-- framing per row. Contents are not read. Shared.
SELECT CAST(COUNT(*) AS BIGINT),
       CAST(COALESCE(SUM(length(s.header) + length(s.signature) + length(s.envelope)
                         + COALESCE(length(s.key_wrap), 0)), 0) AS BIGINT)
FROM vault_snapshots s JOIN vault_vaults v ON v.id = s.vault_id
WHERE v.account_id = $1
