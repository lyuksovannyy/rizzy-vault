-- The (account, class) pairs above $1 rows (ADR 0090 §5): the worker trims each.
SELECT account_id, class
FROM auth_security_events
GROUP BY account_id, class
HAVING COUNT(*) > $1
ORDER BY account_id, class
