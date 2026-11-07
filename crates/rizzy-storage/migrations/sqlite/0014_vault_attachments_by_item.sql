-- The `vault` domain, SQLite: the per-item attachment index (ADR 0093 §1.1 "Storage").
-- Conventions as in 0001_auth_initial.sql.
--
-- `attachments/delete-item` selects at most 16 of one item's attachment rows per transaction
-- by `(vault_id, item_id)`; this index keeps that lookup off a scan of the vault's rows. No
-- column changes, no new table. Numbered 0014: 0013 is taken by the ADR 0092 track, which may
-- land first (migrate.rs).
CREATE INDEX vault_attachments_by_item ON vault_attachments (vault_id, item_id);
