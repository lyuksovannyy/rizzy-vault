-- The `vault` domain, PostgreSQL: vault kinds (ADR 0081 §A10, §A11; Part A, several vaults for
-- one account, none shared). Conventions as in 0001_auth_initial.sql (integers are
-- BIGINT, as every other integer column of this engine).
--
-- ADR 0081 §A10 names this migration `0008_vault_kinds`; 0008 was taken by the WebAuthn tables
-- (ADR 0058, 0077) before it landed, so it takes the next free number, as 0007 did (migrate.rs).
--
-- `kind` is the server's own, unsigned record of what each vault is: 1 the Personal vault (the
-- one signup creates), 2 a vault the account created later. Clients tell the Personal vault
-- apart by their authenticated vault directory (ADR 0081 §A2), never by this column; the server
-- uses it to refuse deleting the Personal vault (INV-101) and to count owned vaults against
-- MAX_OWNED_VAULTS (64). Every existing row becomes kind 1: until now signup was the only path
-- that created a vault, so each account has exactly one. The partial unique index makes the
-- migration fail loudly if that is ever false, and keeps one Personal vault per account after.
ALTER TABLE vault_vaults ADD COLUMN kind BIGINT NOT NULL DEFAULT 1 CHECK (kind IN (1, 2));
CREATE UNIQUE INDEX vault_vaults_personal ON vault_vaults (account_id) WHERE kind = 1;
