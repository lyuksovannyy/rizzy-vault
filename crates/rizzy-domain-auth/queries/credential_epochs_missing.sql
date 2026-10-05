-- The accounts whose credential or recovery row has no account_key_epoch yet: rows migration 0005 found (ADR 0032 §4), filled from the current signed state at startup. Shared by both engines.
SELECT account_id FROM auth_credentials WHERE account_key_epoch IS NULL UNION SELECT account_id FROM auth_recovery WHERE account_key_epoch IS NULL ORDER BY account_id
