-- Restore: one row of `vault_device_cursors` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO vault_device_cursors (vault_id, device_id, cursor, updated_at_ms)
VALUES ($1, $2, $3, $4)
