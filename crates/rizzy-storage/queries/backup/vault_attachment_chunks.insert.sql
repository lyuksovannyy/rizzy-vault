-- Restore: one row of `vault_attachment_chunks` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO vault_attachment_chunks (attachment_id, chunk_index, chunk_envelope)
VALUES ($1, $2, $3)
