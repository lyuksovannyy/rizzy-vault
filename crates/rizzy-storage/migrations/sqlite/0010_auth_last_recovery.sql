-- `rizzy-domain-auth`, SQLite: when the account's last recovery committed (ADR 0045 points 1, 6;
-- CRYPTO.md §11.9 step 6). Conventions as in 0001_auth_initial.sql.
--
-- The value is the server's own, unsigned and advisory (INV-70): it travels in
-- `AccountView.pending_recovery.last_recovery_at_ms` and nothing checks against it. Only the
-- commit of a recovery-only session (the recovery's rotation) writes it; every other rotation
-- leaves it untouched, so a client can tell a recovery apart from a Secret Key change with its
-- default rotation (ADR 0045 point 6). NULL while the account has never been recovered, which
-- is every row this migration finds: no earlier release recorded the time.
ALTER TABLE auth_accounts
    ADD COLUMN last_recovery_at_ms INTEGER CHECK (last_recovery_at_ms IS NULL OR last_recovery_at_ms >= 0);
