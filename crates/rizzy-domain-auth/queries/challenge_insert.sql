-- Stores a device-auth challenge, 60 s TTL (CRYPTO.md §5.10). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_device_challenges (challenge, account_id, device_id, expires_at_ms) VALUES ($1, $2, $3, $4)
