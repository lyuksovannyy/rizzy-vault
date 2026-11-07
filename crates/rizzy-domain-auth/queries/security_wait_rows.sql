-- Every account with the value_new of its newest code 1 or 24 row (NULL when it has none), for the
-- start-up check of the recovery wait (ADR 0090 §6 point 2).
SELECT a.id, (
    SELECT e.value_new FROM auth_security_events e
    WHERE e.account_id = a.id AND e.kind IN (1, 24)
    ORDER BY e.at_ms DESC, e.event_id DESC
    LIMIT 1)
FROM auth_accounts a
ORDER BY a.id
