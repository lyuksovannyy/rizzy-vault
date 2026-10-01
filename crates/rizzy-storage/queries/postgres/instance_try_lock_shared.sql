-- The instance lock in shared mode (ADR 0023 §5 step 1): every server process holds it, at
-- session level, on a dedicated connection outside the pool, for its whole life. Taken without
-- waiting: it is refused only while an admin command (restore, migrate, secrets rotate) holds
-- the exclusive lock. $1 = the instance-lock key K (the single-bigint key space). Returns true
-- when this session now holds the lock.
SELECT pg_try_advisory_lock_shared($1)
