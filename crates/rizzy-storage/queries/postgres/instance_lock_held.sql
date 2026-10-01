-- Whether this session still holds the instance lock in mode $3 (ADR 0023 §5 step 1: "checked
-- alive as ADR 0010 §2 does for the worker lock"). A single-bigint advisory lock shows in
-- pg_locks with classid = the key's high 32 bits ($1), objid = its low 32 bits ($2) and
-- objsubid = 1, in the current database; both halves are bound as non-negative int8, so the
-- oid columns compare equal as int8. $3 = 'ShareLock' or 'ExclusiveLock'.
SELECT EXISTS (
    SELECT 1
    FROM pg_locks
    WHERE locktype = 'advisory'
      AND granted
      AND pid = pg_backend_pid()
      AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
      AND classid::int8 = $1
      AND objid::int8 = $2
      AND objsubid = 1
      AND mode = $3
)
