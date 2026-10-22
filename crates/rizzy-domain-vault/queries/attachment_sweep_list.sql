-- The 24 h sweep of ADR 0054 §7: attachments created before the cutoff whose stored chunks are
-- still fewer than their chunk_count, with their vault's owner, oldest first, at most $2. Shared.
SELECT a.attachment_id, v.account_id
FROM vault_attachments a JOIN vault_vaults v ON v.id = a.vault_id
WHERE a.created_at_ms < $1
  AND (SELECT COUNT(*) FROM vault_attachment_chunks c WHERE c.attachment_id = a.attachment_id)
      < a.chunk_count
ORDER BY a.created_at_ms, a.attachment_id
LIMIT $2
