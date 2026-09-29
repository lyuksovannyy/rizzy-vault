-- Stores or replaces E_id of account $1. Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_identity_keys (account_id, identity_epoch, e_id, updated_at_ms) VALUES ($1, $2, $3, $4) ON CONFLICT (account_id) DO UPDATE SET identity_epoch = excluded.identity_epoch, e_id = excluded.e_id, updated_at_ms = excluded.updated_at_ms
