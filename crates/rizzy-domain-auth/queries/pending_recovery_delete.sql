-- Cancels or closes the pending recovery of account $1. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_pending_recoveries WHERE account_id = $1
