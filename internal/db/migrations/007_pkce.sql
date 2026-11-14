-- +goose Up

-- Add PKCE columns to oauth_codes.
-- Both columns are nullable so that existing codes issued without PKCE continue to work.
ALTER TABLE oauth_codes ADD COLUMN code_challenge        TEXT;
ALTER TABLE oauth_codes ADD COLUMN code_challenge_method TEXT;

-- +goose Down
-- SQLite does not support DROP COLUMN in older versions; a full table rebuild would be
-- required. Since this migration only adds nullable columns, rolling back is a no-op
-- in practice and the down migration is intentionally left as a comment.
-- SELECT 1; -- no-op
