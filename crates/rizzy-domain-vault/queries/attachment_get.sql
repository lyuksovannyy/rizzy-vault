-- One attachment's row with its vault's owner, and the number of chunks stored so far (ADR 0054
-- §5, §6): every endpoint resolves the id through the session's account. Shared.
SELECT a.vault_id, a.item_id, a.attachment_key_wrap, a.total_plaintext_len, a.chunk_count,
       a.created_at_ms, v.account_id,
       (SELECT CAST(COUNT(*) AS BIGINT) FROM vault_attachment_chunks c
        WHERE c.attachment_id = a.attachment_id)
FROM vault_attachments a JOIN vault_vaults v ON v.id = a.vault_id
WHERE a.attachment_id = $1
