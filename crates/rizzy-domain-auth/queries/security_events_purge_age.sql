-- The age rule of ADR 0090 §5: deletes rows older than $1 (at_ms), except each account's newest
-- code 1 or 24 row (the wait in force).
DELETE FROM auth_security_events
WHERE at_ms < $1
  AND event_id NOT IN (
      SELECT (
          SELECT n.event_id FROM auth_security_events n
          WHERE n.account_id = a.account_id AND n.kind IN (1, 24)
          ORDER BY n.at_ms DESC, n.event_id DESC
          LIMIT 1)
      FROM (SELECT DISTINCT account_id FROM auth_security_events WHERE kind IN (1, 24)) a)
