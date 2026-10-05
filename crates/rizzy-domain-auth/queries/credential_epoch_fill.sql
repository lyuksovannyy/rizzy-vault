-- Fills the missing account_key_epoch of account $1's credential row from its current signed state (ADR 0032 §4). Shared by both engines; every value is a bound parameter (INV-53).
UPDATE auth_credentials SET account_key_epoch = $2 WHERE account_id = $1 AND account_key_epoch IS NULL
