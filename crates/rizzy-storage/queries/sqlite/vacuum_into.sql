-- A consistent copy of the whole database into the file named by $1, which must not exist or
-- must be empty (ADR 0011 point 9 and "Backups": `VACUUM INTO`).
VACUUM INTO $1
