-- Every account with a counter row, for the reconciliation pass (ADR 0048 §4). Shared.
SELECT account_id FROM storage_account_usage ORDER BY account_id
