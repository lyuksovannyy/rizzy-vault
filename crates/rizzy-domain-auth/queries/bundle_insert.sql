-- Appends a verified bundle to the chain of account $1. Shared by both engines; every value is a bound parameter (INV-53).
INSERT INTO auth_bundles (account_id, bundle_seq, bundle, stored_at_ms) VALUES ($1, $2, $3, $4)
