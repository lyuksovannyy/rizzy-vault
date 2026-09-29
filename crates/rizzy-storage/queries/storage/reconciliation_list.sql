-- Every open reconciliation epoch, oldest first (for `worker`'s admin-set limit, ADR 0012 §7).
-- Shared by both engines.
SELECT account_id, restore_generation, opened_at_ms
FROM storage_reconciliation
ORDER BY opened_at_ms, account_id
