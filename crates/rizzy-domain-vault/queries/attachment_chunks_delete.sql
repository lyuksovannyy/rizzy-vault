-- Deletes every chunk of one attachment (ADR 0054 §7). Shared.
DELETE FROM vault_attachment_chunks WHERE attachment_id = $1
