-- One account's attachments for the storage counter (ADR 0048 §2, §4; ADR 0054 §6): their number
-- and their counted bytes, each the wrap's length plus every chunk envelope its declared size
-- implies (total_plaintext_len + 90 per chunk), stored yet or not: what `attachments/create`
-- charged. Chunk rows add nothing more. Contents are not read. Shared.
SELECT CAST(COUNT(*) AS BIGINT),
       CAST(COALESCE(SUM(length(a.attachment_key_wrap) + a.total_plaintext_len
                         + 90 * a.chunk_count), 0) AS BIGINT)
FROM vault_attachments a JOIN vault_vaults v ON v.id = a.vault_id
WHERE v.account_id = $1
