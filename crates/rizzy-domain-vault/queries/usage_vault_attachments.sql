-- One vault's attachments for the storage counter (ADR 0048 §2; ADR 0054 §6; ADR 0081 §A5, §A9):
-- as usage_attachments.sql, for one vault. Contents are not read. Shared.
SELECT CAST(COUNT(*) AS BIGINT),
       CAST(COALESCE(SUM(length(a.attachment_key_wrap) + a.total_plaintext_len
                         + 90 * a.chunk_count), 0) AS BIGINT)
FROM vault_attachments a
WHERE a.vault_id = $1
