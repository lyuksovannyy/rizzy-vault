-- 1 when sqlx's migration table exists in the current schema, 0 on a database no migration has
-- touched.
SELECT COUNT(*) FROM pg_catalog.pg_tables
WHERE schemaname = current_schema() AND tablename = '_sqlx_migrations'
