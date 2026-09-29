-- Whether this session still holds the worker's leader lock (ADR 0010 §2: "The worker checks
-- that the connection and the lock are still alive before each job batch"). A two-int4 advisory
-- lock shows in pg_locks with classid = $1, objid = $2 and objsubid = 2, in the current
-- database; both keys are non-negative, so the oid columns compare equal as int8.
SELECT EXISTS (
    SELECT 1
    FROM pg_locks
    WHERE locktype = 'advisory'
      AND granted
      AND pid = pg_backend_pid()
      AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
      AND classid::int8 = $1
      AND objid::int8 = $2
      AND objsubid = 2
)
