-- Healing step 3b deletes the wraps carried with ops below the vault's new epoch: they are under a
-- vault key the restored rotation superseded (ADR 0032 §3). The signed `wrap_hash` stays with the
-- statement. Shared.
UPDATE vault_ops SET key_wrap = NULL WHERE vault_id = $1 AND vault_key_epoch < $2 AND key_wrap IS NOT NULL
