-- Restore: one row of `vault_attachments` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO vault_attachments (attachment_id, vault_id, item_id, attachment_key_wrap, total_plaintext_len, chunk_count, created_at_ms)
VALUES ($1, $2, $3, $4, $5, $6, $7)
