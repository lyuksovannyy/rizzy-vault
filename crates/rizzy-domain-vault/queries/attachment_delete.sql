-- Deletes one attachment's row; its chunks are deleted first (ADR 0054 §7). Shared.
DELETE FROM vault_attachments WHERE attachment_id = $1
