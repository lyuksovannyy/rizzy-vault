-- Deletes the login state $1 in its own transaction after a failure rolled back the one that took it, so it is still used at most once (CRYPTO.md §5.11). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_login_states WHERE login_id = $1
