-- +goose Up

-- Additive only: existing accounts stay verified, so an upgrade changes
-- nothing for them. Only new registrations (when SMTP is configured) set 0.
-- Verification is reporting-only — authentication is never gated on it.
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    token      TEXT     NOT NULL PRIMARY KEY,
    user_id    TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT     NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    used_at    DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS email_verification_tokens_user_id ON email_verification_tokens(user_id);

-- +goose Down

DROP TABLE IF EXISTS email_verification_tokens;

-- SQLite cannot drop a column without rebuilding the table, which would risk
-- the users table on a rollback. The added column is nullable-by-default and
-- harmless if left in place, so the down migration intentionally keeps it.
