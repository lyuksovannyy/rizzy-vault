-- A vault's current self-grant (CRYPTO.md §4.2). Shared.
SELECT account_key_epoch, vault_key_epoch, envelope FROM vault_self_grants WHERE vault_id = $1
