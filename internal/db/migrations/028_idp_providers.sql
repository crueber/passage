-- +goose Up
-- +goose StatementBegin

-- Upstream OIDC/OAuth identity providers, managed in the admin UI.
--
-- client_secret is sealed with the instance's AES-256-GCM key (the same key
-- that protects TOTP secrets), bound to the provider id, so a row copied from
-- one provider to another cannot be decrypted. name is the slug used in the
-- /login/oidc/<name>/... routes and is unique.
CREATE TABLE IF NOT EXISTS idp_providers (
    id            TEXT NOT NULL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    label         TEXT NOT NULL DEFAULT '',
    issuer        TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    scopes        TEXT NOT NULL DEFAULT '',
    auto_create   INTEGER NOT NULL DEFAULT 0,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS idp_providers;
-- +goose StatementEnd
