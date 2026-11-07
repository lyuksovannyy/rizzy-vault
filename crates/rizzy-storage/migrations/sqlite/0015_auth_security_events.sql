-- `rizzy-domain-auth`, SQLite: the per-account security event log (ADR 0090 §4).
-- Conventions as in 0001_auth_initial.sql.
--
-- Advisory and server-written (INV-110); never a secret, a source address or a user agent.
-- One row per recorded action: `kind` is ADR 0090 §3's code, `class` 1 info or 2 alert,
-- `actor_kind` §4's code. Rows go only by the per-(account, class) cap of 500, the 365-day
-- age purge (ADR 0090 §5) and the deletion of their account.
--
-- Backed up (ADR 0090 §11): `tables::TABLES` lists it directly after `auth_accounts`.
CREATE TABLE auth_security_events (
    event_id          BLOB    NOT NULL PRIMARY KEY CHECK (length(event_id) = 16),
    account_id        BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    at_ms             INTEGER NOT NULL CHECK (at_ms >= 0),
    kind              INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 65535),
    class             INTEGER NOT NULL CHECK (class IN (1, 2)),
    actor_kind        INTEGER NOT NULL CHECK (actor_kind BETWEEN 1 AND 255),
    actor_device_id   BLOB    CHECK (actor_device_id IS NULL OR length(actor_device_id) = 16),
    actor_admin_id    BLOB    CHECK (actor_admin_id IS NULL OR length(actor_admin_id) = 16),
    subject_device_id BLOB    CHECK (subject_device_id IS NULL OR length(subject_device_id) = 16),
    label             TEXT    CHECK (label IS NULL OR length(CAST(label AS BLOB)) BETWEEN 1 AND 64),
    value_old         INTEGER CHECK (value_old IS NULL OR value_old >= 0),
    value_new         INTEGER CHECK (value_new IS NULL OR value_new >= 0),
    state_seq         INTEGER CHECK (state_seq IS NULL OR state_seq >= 0)
) STRICT;
CREATE INDEX auth_security_events_list  ON auth_security_events (account_id, at_ms, event_id);
CREATE INDEX auth_security_events_class ON auth_security_events (account_id, class, at_ms, event_id);
CREATE INDEX auth_security_events_age   ON auth_security_events (at_ms);
