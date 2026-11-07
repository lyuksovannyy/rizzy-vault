-- As security_events_page, strictly below the cursor ($4 at_ms, $5 event_id) in (at_ms, event_id) order.
SELECT event_id, at_ms, kind, class, actor_kind, actor_device_id, subject_device_id, label, value_old, value_new, state_seq
FROM auth_security_events
WHERE account_id = $1 AND kind BETWEEN 1 AND $2 AND (at_ms, event_id) < ($4, $5)
ORDER BY at_ms DESC, event_id DESC
LIMIT $3
