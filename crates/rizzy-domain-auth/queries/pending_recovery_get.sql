-- The pending recovery of account $1 (CRYPTO.md §11.9 steps 2-3). Shared by both engines; every value is a bound parameter (INV-53).
SELECT recovery_epoch, opened_at_ms, available_at_ms FROM auth_pending_recoveries WHERE account_id = $1
