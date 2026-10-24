-- `rizzy-domain-auth`, SQLite: WebAuthn security keys as a server-side second factor (ADR 0058,
-- as amended by ADR 0077; CRYPTO.md §11.17). Conventions as in 0001_auth_initial.sql.
--
-- `auth_webauthn_credentials`: one row per enrolled security key (ADR 0077 §4). Nothing here is
-- a secret, so nothing is sealed (ADR 0058 point 1). `security_key` is webauthn-rs's
-- `SecurityKey` as JSON (COSE public key, counter, UV and backup flags, parsed attestation),
-- `security_key_format` its shape (1 = webauthn-rs 0.5.x); `sign_count` is the counter of record
-- INV-83 is decided against. `alg` is ADR 0039 §1's value: only 1 (ES256) is stored (ADR 0077 §6).
-- `label` is the user's name for the key (THREAT_MODEL §3.4 metadata, like `login_name`).
--
-- `auth_webauthn_pending`: the 60 s, single-use second-factor-pending row a login is demoted to
-- after KE3 when the account holds a security key (ADR 0058 point 3). `pending_id` is the
-- login's `login_id`.
--
-- `auth_webauthn_challenges`: the in-progress ceremony state, unsealed, single use, 60 s TTL
-- (ADR 0077 §2). `challenge_id` is the enrolment id (`purpose` 1) or the `pending_id`
-- (`purpose` 2, at most one live per pending row). `state` is webauthn-rs's
-- `SecurityKeyRegistration`/`SecurityKeyAuthentication` as JSON, `state_format` its shape
-- (1 = webauthn-rs 0.5.x). It never leaves the server.
CREATE TABLE auth_webauthn_credentials (
    account_id          BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    credential_id       BLOB    NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1023),
    alg                 INTEGER NOT NULL CHECK (alg = 1),
    security_key        TEXT    NOT NULL,
    security_key_format INTEGER NOT NULL CHECK (security_key_format BETWEEN 0 AND 65535),
    sign_count          INTEGER NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    label               TEXT    NOT NULL,
    created_ms          INTEGER NOT NULL CHECK (created_ms >= 0),
    PRIMARY KEY (account_id, credential_id)
) STRICT;

CREATE TABLE auth_webauthn_pending (
    pending_id    BLOB    NOT NULL PRIMARY KEY CHECK (length(pending_id) = 16),
    account_id    BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0)
) STRICT;
CREATE INDEX auth_webauthn_pending_expiry ON auth_webauthn_pending (expires_at_ms);

CREATE TABLE auth_webauthn_challenges (
    challenge_id  BLOB    NOT NULL PRIMARY KEY CHECK (length(challenge_id) = 16),
    account_id    BLOB    NOT NULL REFERENCES auth_accounts (id) ON DELETE CASCADE,
    purpose       INTEGER NOT NULL CHECK (purpose IN (1, 2)),
    state_format  INTEGER NOT NULL CHECK (state_format BETWEEN 0 AND 65535),
    state         TEXT    NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0)
) STRICT;
CREATE INDEX auth_webauthn_challenges_account ON auth_webauthn_challenges (account_id);
CREATE INDEX auth_webauthn_challenges_expiry ON auth_webauthn_challenges (expires_at_ms);
