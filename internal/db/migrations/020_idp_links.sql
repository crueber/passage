-- +goose Up
-- +goose StatementBegin

-- Links an upstream OIDC/OAuth identity to a local Passage account.
--
-- Purely additive: nothing here alters an existing table, so an upgrade can
-- never take authentication down, and a database with no provider configured
-- simply never reads or writes this table.
--
-- The (provider, subject) pair is the provider's stable identity for a user and
-- is the primary lookup on every external sign-in. subject is the id_token
-- `sub` claim; it is never a token or secret. email is a snapshot for display
-- and diagnostics only — linking by email consults users.email, not this copy.
-- Deleting a user removes their links (ON DELETE CASCADE).
CREATE TABLE IF NOT EXISTS idp_links (
    id         TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    email      TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, subject)
);

CREATE INDEX IF NOT EXISTS idp_links_user_id ON idp_links(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idp_links_user_id;
DROP TABLE IF EXISTS idp_links;
-- +goose StatementEnd
