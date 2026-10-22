-- Backup: every row of `vault_attachment_chunks` (ADR 0054 §5), in primary-key order (ADR 0011 "Backups"). Shared by both engines.
SELECT attachment_id, chunk_index, chunk_envelope
FROM vault_attachment_chunks
ORDER BY attachment_id, chunk_index
