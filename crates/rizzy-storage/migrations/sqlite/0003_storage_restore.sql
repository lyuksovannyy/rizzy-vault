-- `rizzy-storage`'s own tables, SQLite: the restore hooks of ADR 0021 §2 (restore generation)
-- and THREAT_MODEL INV-59 / ADR 0012 §7 (reconciliation epoch). Conventions as in
-- 0001_auth_initial.sql.

-- The restore generation: one random 128-bit value per server database, drawn when the
-- database is created and again by `rizzy-vault restore` (ADR 0021 §2). Exactly one row.
CREATE TABLE storage_meta (
    id                 INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    restore_generation BLOB    NOT NULL CHECK (length(restore_generation) = 16),
    updated_at_ms      INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

-- Accounts in the reconciliation epoch a restore opened (INV-59). A row exists while the epoch
-- is open; `rizzy-domain-auth` ends it by deleting the row (ADR 0012 §7 "End of the
-- reconciliation epoch").
CREATE TABLE storage_reconciliation (
    account_id         BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    restore_generation BLOB    NOT NULL CHECK (length(restore_generation) = 16),
    opened_at_ms       INTEGER NOT NULL CHECK (opened_at_ms >= 0)
) STRICT;
