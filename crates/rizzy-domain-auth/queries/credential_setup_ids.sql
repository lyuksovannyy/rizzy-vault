-- Every setup_id an OPAQUE record names (CRYPTO.md §5.8 startup check). Shared by both engines; every value is a bound parameter (INV-53).
SELECT DISTINCT setup_id FROM auth_credentials
