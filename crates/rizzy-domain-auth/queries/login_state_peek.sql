-- The credential identifier a login state $1 was started for, without taking it, so login finish can take that account's lock first (CRYPTO.md §5.11). Shared by both engines; every value is a bound parameter (INV-53).
SELECT credential_identifier FROM auth_login_states WHERE login_id = $1
