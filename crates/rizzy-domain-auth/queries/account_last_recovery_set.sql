-- Records that a recovery of account $1 committed at $2 (ADR 0045 point 6; CRYPTO.md §11.9 step 6). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_accounts SET last_recovery_at_ms = $2 WHERE id = $1
