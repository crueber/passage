-- +goose Up

-- Per-account colour theme. Empty means "follow the server default", so an
-- upgrade changes nothing for existing users. Additive only.
ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT '';

-- +goose Down

-- SQLite cannot drop a column without rebuilding the table, which would risk
-- the users table on a rollback. The added column defaults to empty and is
-- harmless if left in place, so the down migration intentionally keeps it.
