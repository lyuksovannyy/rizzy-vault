-- `rizzy-domain-auth`, SQLite: the retirement time of an OPAQUE setup (ADR 0031 point 1).
-- Conventions as in 0001_auth_initial.sql.
--
-- `retired_at_ms` is NULL while the setup is accepted, and the time `rizzy-vault secrets
-- retire-setups` retired it otherwise (ADR 0031 point 5 step 1). A setup row is never deleted:
-- it is the tombstone that keeps a retired setup retired (the startup check refuses a secrets
-- file that holds it, point 6), and `auth_credentials.setup_id` still references it.
ALTER TABLE auth_opaque_setups
    ADD COLUMN retired_at_ms INTEGER CHECK (retired_at_ms IS NULL OR retired_at_ms >= 0);
