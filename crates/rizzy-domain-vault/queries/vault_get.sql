-- One vault's owner, current `vault_key_epoch` and store-sequence counter (ADR 0012 §7; ADR 0021
-- §2). Shared by both engines.
SELECT account_id, vault_key_epoch, next_store_seq FROM vault_vaults WHERE id = $1
