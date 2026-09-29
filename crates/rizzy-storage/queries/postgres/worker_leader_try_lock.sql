-- The worker's leader lock (ADR 0010 §2 "One active worker per database"): a session-level
-- advisory lock, taken without waiting, on the worker's dedicated connection outside the pool.
-- $1 = the leader-lock namespace, $2 = its key (the two-int4 key space; the per-account locks
-- use another namespace). Returns true when this session now holds the lock.
SELECT pg_try_advisory_lock($1, $2)
