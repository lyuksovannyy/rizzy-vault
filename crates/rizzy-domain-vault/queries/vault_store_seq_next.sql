-- Advances the per-vault store-sequence counter by one (ADR 0021 §2). Shared.
UPDATE vault_vaults SET next_store_seq = next_store_seq + 1 WHERE id = $1
