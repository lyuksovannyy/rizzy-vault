-- The stored AKE public-key hash of OPAQUE setup $1 and when it was retired, if it was (CRYPTO.md §5.8; ADR 0031 point 1). Shared by both engines; every value is a bound parameter (INV-53).
SELECT ake_public_key_hash, retired_at_ms FROM auth_opaque_setups WHERE setup_id = $1
