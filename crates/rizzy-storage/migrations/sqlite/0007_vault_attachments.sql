-- The `vault` domain's attachment tables, SQLite (ADR 0054 §5; ADR 0011 "Attachments (M3)",
-- answered: DB rows, no separate blob store). Conventions as in 0001_auth_initial.sql.
--
-- `vault_attachments`: one row per declared attachment, from `attachments/create` until
-- `attachments/delete` or the 24 h sweep of an unfinished upload (ADR 0054 §7).
-- `attachment_key_wrap` is the opaque ATTACHMENT_KEY_WRAP envelope (CRYPTO.md §4.2), read back
-- only through `attachments/get`. `total_plaintext_len` is the size the client declared in
-- the clear (THREAT_MODEL §3.4); `chunk_count` = ceil(total_plaintext_len / 524288), derived
-- by the server to size and check the chunks, never fed into an AAD (ADR 0054 §1, §6).
--
-- `vault_attachment_chunks`: one opaque ATTACHMENT_CHUNK envelope per (attachment, index).
CREATE TABLE vault_attachments (
    attachment_id       BLOB    NOT NULL PRIMARY KEY CHECK (length(attachment_id) = 16),
    vault_id            BLOB    NOT NULL REFERENCES vault_vaults (id) ON DELETE CASCADE,
    item_id             BLOB    NOT NULL CHECK (length(item_id) = 16),
    attachment_key_wrap BLOB    NOT NULL,
    total_plaintext_len INTEGER NOT NULL CHECK (total_plaintext_len >= 0),
    chunk_count         INTEGER NOT NULL CHECK (chunk_count >= 0),
    created_at_ms       INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;
CREATE INDEX vault_attachments_vault ON vault_attachments (vault_id);
CREATE INDEX vault_attachments_created ON vault_attachments (created_at_ms);

CREATE TABLE vault_attachment_chunks (
    attachment_id  BLOB    NOT NULL REFERENCES vault_attachments (attachment_id) ON DELETE CASCADE,
    chunk_index    INTEGER NOT NULL CHECK (chunk_index >= 0),
    chunk_envelope BLOB    NOT NULL,
    PRIMARY KEY (attachment_id, chunk_index)
) STRICT;
