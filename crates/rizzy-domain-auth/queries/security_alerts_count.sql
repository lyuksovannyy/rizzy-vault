-- The number of account $1's alert-class rows (class 2) of kinds 1 to $2 younger than $3 (at_ms > $3),
-- for AccountView.security_alerts (ADR 0090 §7).
SELECT COUNT(*)
FROM auth_security_events
WHERE account_id = $1 AND class = 2 AND kind BETWEEN 1 AND $2 AND at_ms > $3
