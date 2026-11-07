-- Closes the revocation window of account $1 (ADR 0091 §2 "Closing"), or deletes its expired row. Shared by both engines; every value is a bound parameter (INV-53).
DELETE FROM auth_revocation_windows WHERE account_id = $1
