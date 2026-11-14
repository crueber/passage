-- +goose Up

-- Per-account default for the My Apps view. Empty means Comfortable; a browser
-- that has chosen its own view stores that choice separately and wins over this
-- account default. Additive only.
ALTER TABLE users ADD COLUMN app_view TEXT NOT NULL DEFAULT '';

-- +goose Down

-- SQLite cannot drop a column without rebuilding the table, which would risk
-- the users table on a rollback. The added column defaults to empty and is
-- harmless if left in place, so the down migration intentionally keeps it.
