-- Backup: every row of `vault_attachments` (ADR 0054 §5), in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT attachment_id, vault_id, item_id, attachment_key_wrap, total_plaintext_len, chunk_count, created_at_ms
FROM vault_attachments
ORDER BY attachment_id
