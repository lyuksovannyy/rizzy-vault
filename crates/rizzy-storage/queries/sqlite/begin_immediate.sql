-- Every SQLite write transaction starts here, on the writer pool of one connection: the
-- database write lock is taken at BEGIN, where `busy_timeout` can wait for it, never at a later
-- lock upgrade that fails with SQLITE_BUSY (ADR 0011 "Transactions and concurrency").
BEGIN IMMEDIATE
