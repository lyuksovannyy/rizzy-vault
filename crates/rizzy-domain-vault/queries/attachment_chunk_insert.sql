-- One chunk envelope (ADR 0054 §6). Shared.
INSERT INTO vault_attachment_chunks (attachment_id, chunk_index, chunk_envelope)
VALUES ($1, $2, $3)
