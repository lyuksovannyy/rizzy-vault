-- The cap of ADR 0090 §5: deletes account $1's rows of class $2 older, in (at_ms, event_id) order,
-- than its newest row of that class at offset $3 (499: the 500th newest), except the account's
-- newest code 1 or 24 row (the wait in force). Nothing when the class has $3 rows or fewer.
DELETE FROM auth_security_events
WHERE account_id = $1
  AND class = $2
  AND (at_ms, event_id) < (
      SELECT at_ms, event_id FROM auth_security_events
      WHERE account_id = $1 AND class = $2
      ORDER BY at_ms DESC, event_id DESC
      LIMIT 1 OFFSET $3)
  AND event_id NOT IN (
      SELECT event_id FROM auth_security_events
      WHERE account_id = $1 AND kind IN (1, 24)
      ORDER BY at_ms DESC, event_id DESC
      LIMIT 1)
