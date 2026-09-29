-- Deletes every pending login state started for credential identifier $1, when its OPAQUE record is replaced: a login started before the change must not finish after it (CRYPTO.md §11.5 step 5, §11.9 step 6, INV-59). Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_login_states WHERE credential_identifier = $1
