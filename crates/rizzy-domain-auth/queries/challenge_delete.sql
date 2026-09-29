-- Deletes the device-auth challenge $1 in its own transaction after a failure rolled back the one that took it, so it is still answered at most once (CRYPTO.md §5.10). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_device_challenges WHERE challenge = $1
