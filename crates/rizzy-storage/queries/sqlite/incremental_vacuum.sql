-- Returns every free page of the file to the filesystem (ADR 0011 "SQLite settings":
-- `auto_vacuum = INCREMENTAL` frees nothing by itself; `worker` runs this after purges). A PRAGMA
-- argument cannot be a bound parameter, so the page count is not configurable: all free pages.
PRAGMA incremental_vacuum
