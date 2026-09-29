-- The stored AKE public-key hash of OPAQUE setup $1 (CRYPTO.md §5.8). Shared by both engines; every value is a bound parameter (INV-53).
SELECT ake_public_key_hash FROM auth_opaque_setups WHERE setup_id = $1
