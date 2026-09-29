-- Reserves a login name for a new account id (CRYPTO.md §11.1 step 4.2). Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_accounts (id, login_name, created_at_ms) VALUES ($1, $2, $3)
