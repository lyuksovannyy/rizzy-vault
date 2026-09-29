-- The open reconciliation epoch of account $1, if any (INV-59). Shared by both engines.
SELECT restore_generation, opened_at_ms FROM storage_reconciliation WHERE account_id = $1
