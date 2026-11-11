-- +goose Up
-- +goose StatementBegin

-- API tokens for the read-only administrative REST API (/api/v1).
--
-- Only the SHA-256 hex digest of a token is stored: the plaintext (`pst_`
-- followed by 32 random bytes, base64url) is shown exactly once at creation.
-- A leaked database therefore yields no usable bearer token, and lookup is a
-- single indexed hit on token_hash instead of a comparison against every row.
--
-- revoked_at is the revocation tombstone: the row is kept so the admin page and
-- the audit log still show which token it was. last_used_at is best-effort and
-- updated by the bearer middleware on each authenticated request.
--
-- Additive only: nothing here alters an existing table, so an upgrade cannot
-- take authentication down and a database that never creates a token behaves
-- exactly as it did before.
CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    revoked_at   DATETIME
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS api_tokens;
-- +goose StatementEnd
