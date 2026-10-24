-- One vault's owner, current `vault_key_epoch`, store-sequence counter and kind (ADR 0012 §7; ADR
-- 0021 §2; ADR 0081 §A10). Shared by both engines.
SELECT account_id, vault_key_epoch, next_store_seq, kind FROM vault_vaults WHERE id = $1
