-- `rizzy-storage`'s own table, PostgreSQL: the per-account storage counter of ADR 0048 §3–§4.
-- Conventions as in 0001_auth_initial.sql.
--
-- One row per account that stored bytes: `bytes_used` is the account's counted bytes (ADR 0048
-- §2, the portable wire size of every row of every table `rizzy-domain-vault` owns), a
-- denormalized sum the stored rows define authoritatively. Only `rizzy_storage::quota` writes it,
-- inside a write transaction holding the account lock. The migration only creates the table: the
-- backfill runs at first startup, each domain summing its own rows (§4), since a `storage_`
-- migration must not read a `vault_` table (ADR 0011 rule 5).
CREATE TABLE storage_account_usage (
    account_id    BYTEA   NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    bytes_used    BIGINT  NOT NULL CHECK (bytes_used >= 0),
    updated_at_ms BIGINT  NOT NULL CHECK (updated_at_ms >= 0)
);
