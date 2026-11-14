-- +goose Up

-- Public, non-secret identifier for admin session-revoke URLs. The session ID
-- IS the bearer token stored in the cookie; embedding it in revoke URLs leaks
-- live credentials to page source, browser history, and access logs. public_id
-- is a random value with no authentication value.

ALTER TABLE sessions ADD COLUMN public_id TEXT;

-- Backfill existing rows with 32 random bytes (64 hex chars).
UPDATE sessions SET public_id = lower(hex(randomblob(32))) WHERE public_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS sessions_public_id ON sessions(public_id);

-- +goose Down

DROP INDEX IF EXISTS sessions_public_id;
ALTER TABLE sessions DROP COLUMN public_id;
