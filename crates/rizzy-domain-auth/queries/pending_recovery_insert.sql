-- Opens a pending recovery with its waiting period (CRYPTO.md §11.9 step 2). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_pending_recoveries (account_id, recovery_epoch, opened_at_ms, available_at_ms) VALUES ($1, $2, $3, $4)
