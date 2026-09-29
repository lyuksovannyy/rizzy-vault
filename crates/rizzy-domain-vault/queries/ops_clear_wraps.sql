-- A rotation deletes the superseded wraps carried with ops (CRYPTO.md §4.2, §11.6 step 9; ADR
-- 0025 §3 step 5). The signed `wrap_hash` stays with the statement. Shared.
UPDATE vault_ops SET key_wrap = NULL WHERE vault_id = $1 AND key_wrap IS NOT NULL
