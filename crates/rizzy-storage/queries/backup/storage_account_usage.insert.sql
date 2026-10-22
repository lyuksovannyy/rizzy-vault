-- Restore: one row of `storage_account_usage` (ADR 0011 "Backups"; ADR 0048 §4). Shared by both engines ($N placeholders).
INSERT INTO storage_account_usage (account_id, bytes_used, updated_at_ms)
VALUES ($1, $2, $3)
