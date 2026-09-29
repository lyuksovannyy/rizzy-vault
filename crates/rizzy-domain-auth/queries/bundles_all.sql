-- The bundle chain of account $1, oldest first (CRYPTO.md §10.2). Shared by both engines; every value is a bound parameter (INV-53).
SELECT bundle_seq, bundle FROM auth_bundles WHERE account_id = $1 ORDER BY bundle_seq
