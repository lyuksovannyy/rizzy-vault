-- Restore: one row of `auth_bundles` (ADR 0011 "Backups"). Shared by both engines ($N placeholders).
INSERT INTO auth_bundles (account_id, bundle_seq, bundle, stored_at_ms)
VALUES ($1, $2, $3, $4)
