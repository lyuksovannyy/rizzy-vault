-- A rotation deletes the superseded wraps carried with snapshots (CRYPTO.md §4.2, §11.6 step 9;
-- ADR 0025 §3 step 5). The signed `wrap_hash` stays. Shared.
UPDATE vault_snapshots SET key_wrap = NULL WHERE vault_id = $1 AND key_wrap IS NOT NULL
