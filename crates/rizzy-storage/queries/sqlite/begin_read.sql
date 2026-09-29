-- A read transaction on the SQLite reader pool. In WAL mode every read inside it sees one
-- snapshot of the database (ADR 0021 §4 "One consistent read").
BEGIN DEFERRED
