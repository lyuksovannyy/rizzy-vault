-- One stored chunk envelope (ADR 0054 §6). Shared.
SELECT chunk_envelope FROM vault_attachment_chunks WHERE attachment_id = $1 AND chunk_index = $2
