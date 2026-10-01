-- The instance lock in exclusive mode (ADR 0023 §5 step 1): restore, migrate and secrets rotate
-- take it, at session level, on their own dedicated connection, and refuse to run when it is
-- not granted, which means a server process (a shared holder) or another admin command still
-- runs. $1 = the instance-lock key K (the single-bigint key space). Returns true when this
-- session now holds the lock.
SELECT pg_try_advisory_lock($1)
