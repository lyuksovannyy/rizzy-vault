-- Deletes ceremony state $1. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_webauthn_challenges WHERE challenge_id = $1
