-- Deletes pending row $1. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_webauthn_pending WHERE pending_id = $1
