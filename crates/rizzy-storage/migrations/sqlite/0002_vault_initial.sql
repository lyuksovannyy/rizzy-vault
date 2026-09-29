-- The `vault` domain's initial M1 schema, SQLite (ADR 0011 "What is stored" as ADR 0022 §2
-- replaces it; ADR 0012 §3, §7; ADR 0021 §2, §3, §6, §7; CRYPTO.md §4.2).
--
-- Tables only: upload, Fetch and compaction belong to `rizzy-domain-vault`. Conventions as in
-- 0001_auth_initial.sql. The clamped VV and the store sequence of ADR 0021 §2 are part of this
-- first vault migration ("one forward migration per engine", ADR 0021 §7).
--
-- Signed records are stored twice over: the canonical header bytes, the hashes and the
-- signature exactly as signed (served verbatim, ADR 0012 §7), and the cleartext header fields
-- the server queries on, copied out of the verified header by `rizzy-domain-vault`.

-- Vaults. `account_id` is the one cross-domain foreign key ADR 0011 point 6 allows.
-- `vault_key_epoch` is the vault's current epoch for the stale-epoch check (ADR 0012 §7,
-- ADR 0021 §9). `next_store_seq` is the per-vault store-sequence counter of ADR 0021 §2.
CREATE TABLE vault_vaults (
    id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
    account_id      BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    vault_key_epoch INTEGER NOT NULL CHECK (vault_key_epoch >= 0),
    next_store_seq  INTEGER NOT NULL DEFAULT 1 CHECK (next_store_seq >= 1),
    created_at_ms   INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;
CREATE INDEX vault_vaults_account ON vault_vaults (account_id);

-- The current `VAULT_KEY_SELF_GRANT` of each vault (CRYPTO.md §4.2, §8.4).
CREATE TABLE vault_self_grants (
    vault_id          BLOB    NOT NULL PRIMARY KEY REFERENCES vault_vaults (id) ON DELETE CASCADE,
    account_key_epoch INTEGER NOT NULL CHECK (account_key_epoch >= 0),
    vault_key_epoch   INTEGER NOT NULL CHECK (vault_key_epoch >= 0),
    envelope          BLOB    NOT NULL,
    updated_at_ms     INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

-- The current `ITEM_KEY_WRAP` set: one row per (vault_id, item_id, item_key_id), holding the
-- wrap under the vault's current `vault_key_epoch` (CRYPTO.md §4.2).
CREATE TABLE vault_item_key_wraps (
    vault_id        BLOB    NOT NULL REFERENCES vault_vaults (id) ON DELETE CASCADE,
    item_id         BLOB    NOT NULL CHECK (length(item_id) = 16),
    item_key_id     BLOB    NOT NULL CHECK (length(item_key_id) = 16),
    vault_key_epoch INTEGER NOT NULL CHECK (vault_key_epoch >= 0),
    envelope        BLOB    NOT NULL,
    updated_at_ms   INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (vault_id, item_id, item_key_id)
) STRICT;

-- Op records under (vault_id, device_id, device_seq) (ADR 0012 §7 "Upload"). The signed header,
-- both hashes and the signature stay for the life of the vault; `body` is NULL once compaction
-- deleted it or when a healing request stored the header without it (a bodiless header, ADR 0021
-- §2); `key_wrap` is NULL when the op carried none or after a rotation superseded it (CRYPTO.md
-- §4.2). `wrap_hash` is 32 zero bytes when the op carried no wrap (ADR 0012 §3).
CREATE TABLE vault_ops (
    vault_id            BLOB    NOT NULL REFERENCES vault_vaults (id) ON DELETE CASCADE,
    device_id           BLOB    NOT NULL CHECK (length(device_id) = 16),
    device_seq          INTEGER NOT NULL CHECK (device_seq >= 1),
    item_id             BLOB    NOT NULL CHECK (length(item_id) = 16),
    op_id               BLOB    NOT NULL CHECK (length(op_id) = 16),
    vault_prev_seq      INTEGER NOT NULL CHECK (vault_prev_seq >= 0),
    hlc                 INTEGER NOT NULL CHECK (hlc >= 0),
    item_schema_version INTEGER NOT NULL CHECK (item_schema_version >= 0),
    vault_key_epoch     INTEGER NOT NULL CHECK (vault_key_epoch >= 0),
    header              BLOB    NOT NULL,
    body_hash           BLOB    NOT NULL CHECK (length(body_hash) = 32),
    wrap_hash           BLOB    NOT NULL CHECK (length(wrap_hash) = 32),
    signature           BLOB    NOT NULL,
    body                BLOB,
    key_wrap            BLOB,
    stored_at_ms        INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    PRIMARY KEY (vault_id, device_id, device_seq)
) STRICT;
CREATE INDEX vault_ops_item ON vault_ops (vault_id, item_id);

-- Retained snapshots (ADR 0012 §3, §7; ADR 0021 §2-§3). The covered VV stays inside the signed
-- `header`; `clamped_vv` is the clamped VV of ADR 0021 §2 in the canonical VV encoding, computed
-- once when the snapshot is stored and never sent; `store_seq` is the per-vault store sequence
-- ("newest" and "oldest" are by it). Retention drops a snapshot by deleting its row (R3).
CREATE TABLE vault_snapshots (
    vault_id            BLOB    NOT NULL REFERENCES vault_vaults (id) ON DELETE CASCADE,
    snapshot_id         BLOB    NOT NULL CHECK (length(snapshot_id) = 16),
    item_id             BLOB    NOT NULL CHECK (length(item_id) = 16),
    author_device_id    BLOB    NOT NULL CHECK (length(author_device_id) = 16),
    item_schema_version INTEGER NOT NULL CHECK (item_schema_version >= 0),
    vault_key_epoch     INTEGER NOT NULL CHECK (vault_key_epoch >= 0),
    header              BLOB    NOT NULL,
    envelope            BLOB    NOT NULL,
    wrap_hash           BLOB    NOT NULL CHECK (length(wrap_hash) = 32),
    signature           BLOB    NOT NULL,
    key_wrap            BLOB,
    clamped_vv          BLOB    NOT NULL,
    store_seq           INTEGER NOT NULL CHECK (store_seq >= 1),
    stored_at_ms        INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    PRIMARY KEY (vault_id, snapshot_id),
    UNIQUE (vault_id, store_seq)
) STRICT;
CREATE INDEX vault_snapshots_item ON vault_snapshots (vault_id, item_id, store_seq);

-- Items `api` queued for the `worker` compaction job after storing a snapshot (ADR 0021 §3
-- "Where it runs").
CREATE TABLE vault_compaction_queue (
    vault_id     BLOB    NOT NULL REFERENCES vault_vaults (id) ON DELETE CASCADE,
    item_id      BLOB    NOT NULL CHECK (length(item_id) = 16),
    queued_at_ms INTEGER NOT NULL CHECK (queued_at_ms >= 0),
    PRIMARY KEY (vault_id, item_id)
) STRICT;

-- Per-device cursors (ADR 0012 §7 "Fetch"; THREAT_MODEL §3.4): the last cursor a device fetched
-- from, in the canonical VV encoding.
CREATE TABLE vault_device_cursors (
    vault_id      BLOB    NOT NULL REFERENCES vault_vaults (id) ON DELETE CASCADE,
    device_id     BLOB    NOT NULL CHECK (length(device_id) = 16),
    cursor        BLOB    NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY (vault_id, device_id)
) STRICT;
