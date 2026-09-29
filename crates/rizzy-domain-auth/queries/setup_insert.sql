-- Records an OPAQUE setup's AKE public-key hash (CRYPTO.md §5.8). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_opaque_setups (setup_id, ake_public_key_hash, created_at_ms) VALUES ($1, $2, $3)
