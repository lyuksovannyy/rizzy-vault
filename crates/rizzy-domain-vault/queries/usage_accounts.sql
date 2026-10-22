-- Every account that owns a vault, for the storage counter's backfill and reconciliation
-- (ADR 0048 §4). Shared.
SELECT DISTINCT account_id FROM vault_vaults ORDER BY account_id
