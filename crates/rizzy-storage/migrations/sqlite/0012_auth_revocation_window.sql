-- `rizzy-domain-auth`, SQLite: the account's revocation window (ADR 0091 §2 "State").
-- Conventions as in 0001_auth_initial.sql.
--
-- At most one row per account. A successful `devices/suspend` opens or renews it; the
-- revocation commit, a recovery commit and the `devices/unsuspend` that leaves no suspended
-- durable device delete it. A window is open while `now_ms < expires_at_ms`; an expired row
-- counts as absent and the next write that reads it deletes it.
--
-- Ephemeral: the backup's `TABLES` list leaves it out (`tables::NOT_BACKED_UP`), as it leaves
-- out sessions and device challenges, so a restore never revives a window.
CREATE TABLE auth_revocation_windows (
    account_id        BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    revoker_device_id BLOB    NOT NULL CHECK (length(revoker_device_id) = 16),
    opened_at_ms      INTEGER NOT NULL CHECK (opened_at_ms >= 0),
    expires_at_ms     INTEGER NOT NULL CHECK (expires_at_ms > opened_at_ms)
) STRICT;
