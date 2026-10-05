-- Healing step 3b deletes the wraps carried with snapshots below the vault's new epoch (ADR 0032
-- §3). The signed `wrap_hash` stays. Shared.
UPDATE vault_snapshots SET key_wrap = NULL WHERE vault_id = $1 AND vault_key_epoch < $2 AND key_wrap IS NOT NULL
