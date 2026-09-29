-- Ends the reconciliation epoch of account $1 (ADR 0012 §7 "End of the reconciliation epoch").
-- Shared by both engines.
DELETE FROM storage_reconciliation WHERE account_id = $1
