-- `rizzy-domain-auth`, SQLite: the `account_key_epoch` of the OPAQUE record with `E_srv`, and
-- of `H_rec` with `E_rec` (ADR 0032 §4). Conventions as in 0001_auth_initial.sql.
--
-- Every credential replacement writes the column from the signed `account-state` of its commit
-- (CRYPTO.md §11 "Replacing credentials"). A row lags its signed state when its
-- (`password_epoch`, `kdf_id`, `account_key_epoch`), or its (`recovery_epoch`,
-- `account_key_epoch`), is not the state's: possible only after a restore to before a
-- credential change or a key rotation. While the record lags, `login/finish` answers
-- `credentials_stale` after KE3; while the recovery row lags, `recovery/start` is refused like
-- a wrong code.
--
-- The column is NULL in the rows this migration finds: the value lives inside the signed state,
-- which SQL cannot read. `rizzy-domain-auth` fills every NULL from the account's current state
-- at each server start, before anything is served (`AuthService::fill_credential_epochs`), as
-- ADR 0032 §4's "a migration fills existing rows from the current state". Until then, a NULL is
-- read as lagging (fail closed).
ALTER TABLE auth_credentials
    ADD COLUMN account_key_epoch INTEGER CHECK (account_key_epoch IS NULL OR account_key_epoch >= 0);
ALTER TABLE auth_recovery
    ADD COLUMN account_key_epoch INTEGER CHECK (account_key_epoch IS NULL OR account_key_epoch >= 0);
