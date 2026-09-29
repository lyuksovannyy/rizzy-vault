-- The per-account lock (ADR 0011 "Transactions and concurrency"): a transaction-level advisory
-- lock, released at commit or rollback, in the two-int4 key space ($1 = the account-lock
-- namespace, $2 = the key derived from the account id). PostgreSQL's single-bigint key space,
-- which sqlx's migrator uses, does not overlap it.
SELECT pg_advisory_xact_lock($1, $2)
