-- +goose Up

-- Invitations let an administrator create an account by mail without enabling
-- public registration. The row is the invite: no users row exists until the
-- recipient opens the link and chooses credentials. Additive only — an upgrade
-- adds an empty table and changes nothing else.
CREATE TABLE IF NOT EXISTS invitations (
    id          TEXT     NOT NULL PRIMARY KEY,
    token       TEXT     NOT NULL UNIQUE,
    email       TEXT     NOT NULL,
    name        TEXT     NOT NULL DEFAULT '',
    invited_by  TEXT     NOT NULL DEFAULT '',
    expires_at  DATETIME NOT NULL,
    accepted_at DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS invitations_email ON invitations(email);

-- An address can have at most one live invitation. Re-inviting replaces the
-- earlier pending row (the store deletes it in the same transaction); a
-- consumed invitation keeps accepted_at, so the same person can be invited
-- again later if their account is removed.
CREATE UNIQUE INDEX IF NOT EXISTS invitations_pending_email
    ON invitations(email) WHERE accepted_at IS NULL;

-- +goose Down

DROP TABLE IF EXISTS invitations;
