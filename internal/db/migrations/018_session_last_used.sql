-- +goose Up

-- Idle-session tracking. last_used_at is refreshed at most once every five
-- minutes per session while it is in use; a session whose last_used_at is
-- older than the configured idle window is treated as expired.
--
-- Nullable on purpose: `ALTER TABLE ... ADD COLUMN` cannot default to another
-- column, and rows written by a binary that predates this migration do not
-- have a value. The backfill below copies created_at so every existing session
-- starts with a well-defined "last used" time (it was, after all, in use at
-- creation), and the service treats a NULL as created_at defensively.
--
-- No index: the only range scan over this column is the periodic idle sweep,
-- which runs hourly and compares COALESCE(last_used_at, created_at) — an
-- expression SQLite cannot index. The per-request touch updates by primary key.

ALTER TABLE sessions ADD COLUMN last_used_at DATETIME;

UPDATE sessions SET last_used_at = created_at WHERE last_used_at IS NULL;

-- +goose Down

-- SQLite cannot drop a column without rebuilding the table. Leave last_used_at
-- in place: it is nullable and ignored by older binaries, so the schema stays
-- usable after a downgrade.
