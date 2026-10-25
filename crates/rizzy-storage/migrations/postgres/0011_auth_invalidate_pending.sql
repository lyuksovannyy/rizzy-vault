-- `rizzy-domain-auth`, PostgreSQL: the crash marker of `rizzy-vault secrets invalidate` (ADR 0047
-- "New: `auth_invalidate_pending`"). Conventions as in 0001_auth_initial.sql.
--
-- ADR 0047 names this migration `0006_auth_invalidate_pending`, a provisional number; 0006 to 0010
-- were taken before it was accepted, so it takes the next free number, as 0007 and 0009 did
-- (migrate.rs).
--
-- At most one row (`id = 1`). `invalidate` step 4 writes it in the transaction that retires
-- every setup and records the new one; step 6 deletes it once the new secrets file is written.
-- A row left behind means a crash between the two: the next run resumes the recorded case
-- instead of diagnosing the file again. `loss_case` is ADR 0047's `case` (a reserved word in
-- SQL): 1 a setup-only loss, 2 a whole loss. `setup_id` is the setup that run minted; it is
-- not a foreign key, so the marker never holds a setup row in place.
CREATE TABLE auth_invalidate_pending (
    id              BIGINT NOT NULL PRIMARY KEY CHECK (id = 1),
    loss_case       BIGINT NOT NULL CHECK (loss_case IN (1, 2)),
    setup_id        BIGINT NOT NULL CHECK (setup_id >= 1),
    diagnosed_at_ms BIGINT NOT NULL CHECK (diagnosed_at_ms >= 0)
);
