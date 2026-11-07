-- `rizzy-domain-vault`, SQLite: rotation staging (ADR 0092 §4). Conventions as in
-- 0002_vault_initial.sql.
--
-- A staging holds the re-wrapped rows of one rotation ahead of its `account/commit`, when the
-- inline commit body would exceed 32 MiB. Staged rows are not state: no Fetch, recovery read,
-- export, compaction or quota reads them, and they change nothing until the commit applies them
-- and deletes the staging in one transaction. At most one staging per account
-- (`vault_rotation_stagings`, its fixed `(rotation_id, base_state_seq, account_key_id)`
-- triple and `last_stage_at_ms`); per vault the `vault_key_epoch` its first stage request
-- fixed (`vault_rotation_staging_vaults`); per row the locator and the wrap, NULL for a dropped
-- row (`vault_rotation_staging`). Any commit that advances `state_seq` deletes the account's
-- staging; the worker deletes one whose `last_stage_at_ms` is older than
-- `ROTATION_STAGE_TTL_MS`.
--
-- Ephemeral: the backup's `TABLES` list leaves all three out (`tables::NOT_BACKED_UP`), as it
-- leaves out the revocation window, so a restore never revives a staging (it would name a
-- `state_seq` the restored state may not have).
CREATE TABLE vault_rotation_stagings (
    account_id       BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    rotation_id      BLOB    NOT NULL CHECK (length(rotation_id) = 16),
    base_state_seq   INTEGER NOT NULL CHECK (base_state_seq >= 0),
    account_key_id   BLOB    NOT NULL CHECK (length(account_key_id) = 16),
    last_stage_at_ms INTEGER NOT NULL CHECK (last_stage_at_ms >= 0)
) STRICT;

CREATE TABLE vault_rotation_staging_vaults (
    account_id      BLOB    NOT NULL REFERENCES vault_rotation_stagings (account_id) ON DELETE CASCADE,
    vault_id        BLOB    NOT NULL REFERENCES vault_vaults (id) ON DELETE CASCADE,
    vault_key_epoch INTEGER NOT NULL CHECK (vault_key_epoch >= 0),
    PRIMARY KEY (account_id, vault_id)
) STRICT;

CREATE TABLE vault_rotation_staging (
    account_id  BLOB NOT NULL,
    rotation_id BLOB NOT NULL CHECK (length(rotation_id) = 16),
    vault_id    BLOB NOT NULL,
    item_id     BLOB NOT NULL CHECK (length(item_id) = 16),
    item_key_id BLOB NOT NULL CHECK (length(item_key_id) = 16),
    wrap        BLOB,
    PRIMARY KEY (account_id, vault_id, item_id, item_key_id),
    FOREIGN KEY (account_id, vault_id)
        REFERENCES vault_rotation_staging_vaults (account_id, vault_id) ON DELETE CASCADE
) STRICT;
