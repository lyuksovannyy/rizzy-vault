-- Every device certificate of account $1 with its kind, suspension and storage time, by device id. Shared by both engines; every value is a bound parameter (INV-53).
SELECT device_id, device_kind, certificate, suspended_at_ms, stored_at_ms FROM auth_device_certificates WHERE account_id = $1 ORDER BY device_id
