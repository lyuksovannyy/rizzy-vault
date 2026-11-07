-- The revocation window of account $1, open or expired (ADR 0091 §2). Shared by both engines; every value is a bound parameter (INV-53).
SELECT revoker_device_id, opened_at_ms, expires_at_ms FROM auth_revocation_windows WHERE account_id = $1
