-- The migration versions sqlx has recorded, with their success flag and checksum. Shared by
-- both engines.
SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version
