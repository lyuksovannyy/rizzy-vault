-- The wrap-set rows of every vault an account owns (ADR 0092 §1 "A wrap-set row", §2 check 2):
-- the rows of a vault count against the account that owns it. Contents are not read. Shared.
SELECT CAST(COUNT(*) AS BIGINT)
FROM vault_item_key_wraps w JOIN vault_vaults v ON v.id = w.vault_id
WHERE v.account_id = $1
