-- Clears rate-limit bucket $1 after a success. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_rate_limits WHERE bucket = $1
