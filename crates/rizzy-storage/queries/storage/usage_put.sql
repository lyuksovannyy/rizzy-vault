-- Sets one account's counted bytes, inserting its row on first use (ADR 0048 §3). Shared.
INSERT INTO storage_account_usage (account_id, bytes_used, updated_at_ms)
VALUES ($1, $2, $3)
ON CONFLICT (account_id) DO UPDATE
SET bytes_used = excluded.bytes_used, updated_at_ms = excluded.updated_at_ms
