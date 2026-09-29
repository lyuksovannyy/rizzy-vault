-- A read transaction on PostgreSQL: every read inside it sees one snapshot (ADR 0021 §4 "One
-- consistent read": a read-only REPEATABLE READ transaction).
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY
