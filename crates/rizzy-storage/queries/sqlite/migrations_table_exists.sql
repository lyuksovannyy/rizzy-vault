-- 1 when sqlx's migration table exists, 0 on a database no migration has touched.
SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'
