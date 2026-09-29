-- A vault's first self-grant. Shared.
INSERT INTO vault_self_grants (vault_id, account_key_epoch, vault_key_epoch, envelope, updated_at_ms)
VALUES ($1, $2, $3, $4, $5)
