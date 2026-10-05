-- Restore: one row of `auth_opaque_setups` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_opaque_setups (setup_id, ake_public_key_hash, created_at_ms, retired_at_ms)
VALUES ($1, $2, $3, $4)
