-- Suspends device $2 of account $1 (CRYPTO.md §11.8 step 0), keeping an earlier suspension time. Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_device_certificates SET suspended_at_ms = $3 WHERE account_id = $1 AND device_id = $2 AND suspended_at_ms IS NULL
