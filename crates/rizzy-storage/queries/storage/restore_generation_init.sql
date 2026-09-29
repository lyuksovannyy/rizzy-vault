-- Draws the database's first restore generation (ADR 0021 §2): inserts $1 unless a value
-- already exists. Shared by both engines.
INSERT INTO storage_meta (id, restore_generation, updated_at_ms)
VALUES (1, $1, $2)
ON CONFLICT (id) DO NOTHING
