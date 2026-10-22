-- One account's counted bytes (ADR 0048 §3); no row reads as 0. Shared.
SELECT bytes_used FROM storage_account_usage WHERE account_id = $1
