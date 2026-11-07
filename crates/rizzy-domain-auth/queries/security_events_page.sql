-- A page of account $1's security events (ADR 0090 §7), newest first: kinds 1 to $2 (the ones this
-- build knows), at most $3 rows.
SELECT event_id, at_ms, kind, class, actor_kind, actor_device_id, subject_device_id, label, value_old, value_new, state_seq
FROM auth_security_events
WHERE account_id = $1 AND kind BETWEEN 1 AND $2
ORDER BY at_ms DESC, event_id DESC
LIMIT $3
