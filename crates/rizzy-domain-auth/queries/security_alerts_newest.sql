-- The newest of the rows security_alerts_count counts: event_id, at_ms, kind.
SELECT event_id, at_ms, kind
FROM auth_security_events
WHERE account_id = $1 AND class = 2 AND kind BETWEEN 1 AND $2 AND at_ms > $3
ORDER BY at_ms DESC, event_id DESC
LIMIT 1
