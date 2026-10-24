-- When the last recovery of account $1 committed (ADR 0045 point 6), NULL if none did. Shared by both engines; every value is a bound parameter (INV-53).
SELECT last_recovery_at_ms FROM auth_accounts WHERE id = $1
