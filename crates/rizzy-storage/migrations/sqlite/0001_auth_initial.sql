-- The `auth` domain's initial M1 schema, SQLite (ADR 0011 "What is stored" as ADR 0022 §2
-- replaces it; ADR 0010 §5; CRYPTO.md §4.2, §5.8-§5.11, §10, §11).
--
-- Tables only: the rules that fill and read them belong to `rizzy-domain-auth`. Conventions
-- (ADR 0011 point 4, "No plaintext"):
--   * ids are 16-byte BLOBs created by the client (or by the server's CSPRNG for server ids);
--   * envelopes, signed statements and hashes are BLOBs, stored as the client or `rizzy-core`
--     encodes them; no TEXT column holds user content (`login_name` is THREAT_MODEL §3.4
--     metadata);
--   * times are INTEGER milliseconds since the Unix epoch, set by the server;
--   * u32 epochs and u64 sequence numbers are INTEGER; a u64 above i64::MAX is refused before
--     it reaches SQL (`rizzy_storage::convert`), so every stored value is >= 0;
--   * STRICT tables, so SQLite refuses a value of the wrong storage class.
-- Every table except `auth_opaque_setups`, `auth_login_states` and `auth_rate_limits` hangs off
-- `auth_accounts` with ON DELETE CASCADE, so deleting an account is one statement (ADR 0011
-- point 6).

-- Accounts. `login_name` is the normalised login name (CRYPTO.md §2, §5.9).
CREATE TABLE auth_accounts (
    id            BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
    login_name    TEXT    NOT NULL UNIQUE CHECK (length(login_name) > 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

-- One row per OPAQUE `server_setup` the server has loaded (CRYPTO.md §5.8): the database stores
-- SHA-256 of the setup's AKE public key, never the setup itself (INV-50).
CREATE TABLE auth_opaque_setups (
    setup_id            INTEGER NOT NULL PRIMARY KEY CHECK (setup_id >= 0),
    ake_public_key_hash BLOB    NOT NULL CHECK (length(ake_public_key_hash) = 32),
    created_at_ms       INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

-- The OPAQUE registration record and `E_srv`, which are replaced together under the
-- credential-replacement rule (CRYPTO.md §11), with the `setup_id`, `kdf_id` and
-- `password_epoch` stored beside the record (CRYPTO.md §11.1 step 8, INV-59).
CREATE TABLE auth_credentials (
    account_id     BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    setup_id       INTEGER NOT NULL REFERENCES auth_opaque_setups (setup_id),
    opaque_record  BLOB    NOT NULL,
    kdf_id         INTEGER NOT NULL CHECK (kdf_id >= 0),
    password_epoch INTEGER NOT NULL CHECK (password_epoch >= 0),
    e_srv          BLOB    NOT NULL,
    updated_at_ms  INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

-- `E_id`, the identity secret keys under the account key (CRYPTO.md §4.2, §8.4).
CREATE TABLE auth_identity_keys (
    account_id     BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    identity_epoch INTEGER NOT NULL CHECK (identity_epoch >= 0),
    e_id           BLOB    NOT NULL,
    updated_at_ms  INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

-- `E_rec` and `H_rec = SHA-256(recovery_auth_token)`, with the `recovery_epoch` stored beside
-- `H_rec` (CRYPTO.md §11, §11.9). No row while no recovery code is valid.
CREATE TABLE auth_recovery (
    account_id     BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    e_rec          BLOB    NOT NULL,
    h_rec          BLOB    NOT NULL CHECK (length(h_rec) = 32),
    updated_at_ms  INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

-- The signed public-key bundle chain (CRYPTO.md §10.2 "Bundles are a chain"). Every bundle is
-- kept, so a verifier can fetch the chain from the `bundle_seq` it pinned.
CREATE TABLE auth_bundles (
    account_id   BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    bundle_seq   INTEGER NOT NULL CHECK (bundle_seq >= 1),
    bundle       BLOB    NOT NULL,
    stored_at_ms INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    PRIMARY KEY (account_id, bundle_seq)
) STRICT;

-- The current signed `account-state` (CRYPTO.md §10.2), replaced by compare-and-swap on
-- `state_seq` under the account lock (ADR 0011 "Transactions and concurrency").
CREATE TABLE auth_account_states (
    account_id    BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    state_seq     INTEGER NOT NULL CHECK (state_seq >= 1),
    statement     BLOB    NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

-- The current `ACCOUNT_SETTINGS` envelope (CRYPTO.md §4.2, §10.2 "Settings freshness"). No row
-- while `settings_seq` is 0.
CREATE TABLE auth_account_settings (
    account_id    BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    settings_seq  INTEGER NOT NULL CHECK (settings_seq >= 1),
    envelope      BLOB    NOT NULL,
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

-- `RETIRED_SECRET_KEY` envelopes, located by the retired public key id (CRYPTO.md §8.4, §11.6
-- step 3).
CREATE TABLE auth_retired_secret_keys (
    account_id     BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    retired_key_id BLOB    NOT NULL CHECK (length(retired_key_id) = 16),
    envelope       BLOB    NOT NULL,
    stored_at_ms   INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    PRIMARY KEY (account_id, retired_key_id)
) STRICT;

-- The current device certificate of each device (CRYPTO.md §10.2 `device-certificate`), with
-- the cleartext fields the server checks copied out of it, and the server-side suspension of
-- revocation phase 1 (ADR 0012 §6, CRYPTO.md §11.8 step 0). `expires_at_ms` is 0 for none.
CREATE TABLE auth_device_certificates (
    account_id      BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    device_id       BLOB    NOT NULL CHECK (length(device_id) = 16),
    identity_epoch  INTEGER NOT NULL CHECK (identity_epoch >= 0),
    device_kind     INTEGER NOT NULL CHECK (device_kind BETWEEN 1 AND 4),
    expires_at_ms   INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    certificate     BLOB    NOT NULL,
    suspended_at_ms INTEGER CHECK (suspended_at_ms >= 0),
    stored_at_ms    INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    PRIMARY KEY (account_id, device_id)
) STRICT;

-- Signed `device-revocation` statements, with their `last_accepted_device_seq` copied out
-- (CRYPTO.md §10.2, §11.8; ADR 0021 §9 "Revoked and kind-4 authors").
CREATE TABLE auth_device_revocations (
    account_id               BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    device_id                BLOB    NOT NULL CHECK (length(device_id) = 16),
    last_accepted_device_seq INTEGER NOT NULL CHECK (last_accepted_device_seq >= 0),
    revocation               BLOB    NOT NULL,
    stored_at_ms             INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    PRIMARY KEY (account_id, device_id)
) STRICT;

-- `ACCOUNT_KEY_DEVICE_GRANT`s, kept until the recipient device acknowledges them (CRYPTO.md
-- §4.2, §10.1, §11.6 step 6). `grant_record` is the HPKE envelope with its `key-grant`
-- signature, as the client uploaded them.
CREATE TABLE auth_key_grants (
    account_id          BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    recipient_device_id BLOB    NOT NULL CHECK (length(recipient_device_id) = 16),
    account_key_epoch   INTEGER NOT NULL CHECK (account_key_epoch >= 0),
    sender_device_id    BLOB    NOT NULL CHECK (length(sender_device_id) = 16),
    grant_record        BLOB    NOT NULL,
    stored_at_ms        INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    PRIMARY KEY (account_id, recipient_device_id, account_key_epoch)
) STRICT;

-- Sessions (CRYPTO.md §5.10): only SHA-256 of the bearer token (INV-8), the 16-byte
-- `session_id` of request signing, the device a device-authenticated session is for, and the
-- request-counter window. `session_kind` and the window encoding are `rizzy-domain-auth`'s.
CREATE TABLE auth_sessions (
    token_hash             BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
    session_id             BLOB    NOT NULL UNIQUE CHECK (length(session_id) = 16),
    account_id             BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    device_id              BLOB    CHECK (length(device_id) = 16),
    session_kind           INTEGER NOT NULL CHECK (session_kind >= 0),
    created_at_ms          INTEGER NOT NULL CHECK (created_at_ms >= 0),
    expires_at_ms          INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    request_counter_max    INTEGER CHECK (request_counter_max >= 0),
    request_counter_window INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX auth_sessions_account ON auth_sessions (account_id);
CREATE INDEX auth_sessions_expiry ON auth_sessions (expires_at_ms);

-- Server-side TOTP credentials, sealed as `SERVER_TOTP_SECRET` under the server data key named
-- by `data_key_id` (CRYPTO.md §5.11, §11.15), with the last accepted time step.
CREATE TABLE auth_totp_credentials (
    account_id          BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    totp_credential_seq INTEGER NOT NULL CHECK (totp_credential_seq >= 1),
    data_key_id         INTEGER NOT NULL CHECK (data_key_id >= 0),
    sealed_secret       BLOB    NOT NULL,
    last_accepted_step  INTEGER CHECK (last_accepted_step >= 0),
    created_at_ms       INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY (account_id, totp_credential_seq)
) STRICT;

-- Short-lived auth state (ADR 0010 §5). OPAQUE `ServerLogin` state, sealed as
-- `SERVER_LOGIN_STATE` (CRYPTO.md §5.10, §5.11), 60 s TTL. `credential_identifier` is part of
-- the seal's context; it is the account id or the fake-record id (CRYPTO.md §5.9), so this table
-- has no foreign key.
CREATE TABLE auth_login_states (
    login_id              BLOB    NOT NULL PRIMARY KEY CHECK (length(login_id) = 16),
    credential_identifier BLOB    NOT NULL CHECK (length(credential_identifier) = 16),
    data_key_id           INTEGER NOT NULL CHECK (data_key_id >= 0),
    sealed_state          BLOB    NOT NULL,
    expires_at_ms         INTEGER NOT NULL CHECK (expires_at_ms >= 0)
) STRICT;
CREATE INDEX auth_login_states_expiry ON auth_login_states (expires_at_ms);

-- Device-auth challenges, 60 s TTL (CRYPTO.md §5.10).
CREATE TABLE auth_device_challenges (
    challenge     BLOB    NOT NULL PRIMARY KEY CHECK (length(challenge) = 32),
    account_id    BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    device_id     BLOB    NOT NULL CHECK (length(device_id) = 16),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0)
) STRICT;
CREATE INDEX auth_device_challenges_expiry ON auth_device_challenges (expires_at_ms);

-- Rate-limit and backoff counters per (account, source) and per-IP signup limits (ADR 0010 §5,
-- CRYPTO.md §5.9). `bucket` is an opaque key `rizzy-domain-auth` derives; no account foreign key,
-- because signup buckets have no account.
CREATE TABLE auth_rate_limits (
    bucket               BLOB    NOT NULL PRIMARY KEY CHECK (length(bucket) BETWEEN 1 AND 64),
    attempts             INTEGER NOT NULL CHECK (attempts >= 0),
    window_started_at_ms INTEGER NOT NULL CHECK (window_started_at_ms >= 0),
    blocked_until_ms     INTEGER NOT NULL CHECK (blocked_until_ms >= 0),
    expires_at_ms        INTEGER NOT NULL CHECK (expires_at_ms >= 0)
) STRICT;
CREATE INDEX auth_rate_limits_expiry ON auth_rate_limits (expires_at_ms);

-- Pending recoveries and their waiting periods (CRYPTO.md §11.9 steps 2-3).
CREATE TABLE auth_pending_recoveries (
    account_id      BLOB    NOT NULL PRIMARY KEY REFERENCES auth_accounts (id) ON DELETE CASCADE,
    recovery_epoch  INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    opened_at_ms    INTEGER NOT NULL CHECK (opened_at_ms >= 0),
    available_at_ms INTEGER NOT NULL CHECK (available_at_ms >= opened_at_ms)
) STRICT;
