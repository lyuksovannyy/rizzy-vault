-- Ends every session of kind $2 of account $1 except the session whose token hashes to $3. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_sessions WHERE account_id = $1 AND session_kind = $2 AND token_hash <> $3
