-- +goose Up

-- Add per-app session duration override to the apps table.
-- A value of 0 means "use the global session_duration_hours setting".
ALTER TABLE apps ADD COLUMN session_duration_hours INTEGER NOT NULL DEFAULT 0;

-- +goose Down
-- SQLite does not support DROP COLUMN without a full table rebuild.
-- Since this migration only adds a NOT NULL column with a DEFAULT,
-- rolling back is a no-op in practice.
SELECT 1; -- no-op
