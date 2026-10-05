-- Deletes every sealed login state, so no login started under a setup being retired finishes (ADR 0031 point 5 step 1). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_login_states
