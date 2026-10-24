-- Deletes account $1's ceremony states of purpose $2: a new enrolment replaces an unfinished one. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_webauthn_challenges WHERE account_id = $1 AND purpose = $2
