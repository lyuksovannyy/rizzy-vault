-- Puts every account into a reconciliation epoch (THREAT_MODEL INV-59), in the restore
-- transaction. $1 = the new restore generation, $2 = now. Shared by both engines.
INSERT INTO storage_reconciliation (account_id, restore_generation, opened_at_ms)
SELECT id, $1, $2 FROM auth_accounts
