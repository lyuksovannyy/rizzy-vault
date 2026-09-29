-- Lifts the suspension of device $2 of account $1 (ADR 0012 §6: only a fresh session of another device in the set). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_device_certificates SET suspended_at_ms = NULL WHERE account_id = $1 AND device_id = $2
