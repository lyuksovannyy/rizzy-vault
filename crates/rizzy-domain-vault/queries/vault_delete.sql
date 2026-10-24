-- Deletes one vault; its self-grant, wraps, ops, snapshots, compaction queue rows, device cursors,
-- attachments and their chunks go with it by ON DELETE CASCADE (ADR 0081 §A5). Shared.
DELETE FROM vault_vaults WHERE id = $1
