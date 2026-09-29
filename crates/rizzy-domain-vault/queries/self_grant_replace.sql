-- Replaces a vault's self-grant. Shared.
UPDATE vault_self_grants SET account_key_epoch = $2, vault_key_epoch = $3, envelope = $4, updated_at_ms = $5
WHERE vault_id = $1
