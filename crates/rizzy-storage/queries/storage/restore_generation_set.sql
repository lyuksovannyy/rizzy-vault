-- Replaces the restore generation; only `restore` calls it, after loading the rows (ADR 0021
-- §2). Shared by both engines.
INSERT INTO storage_meta (id, restore_generation, updated_at_ms)
VALUES (1, $1, $2)
ON CONFLICT (id) DO UPDATE
SET restore_generation = excluded.restore_generation, updated_at_ms = excluded.updated_at_ms
