-- +goose Up
-- +goose StatementBegin

ALTER TABLE apps ADD COLUMN client_id            TEXT DEFAULT NULL;
ALTER TABLE apps ADD COLUMN client_secret_hash   TEXT DEFAULT NULL;
ALTER TABLE apps ADD COLUMN redirect_uris        TEXT NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN oauth_enabled        INTEGER NOT NULL DEFAULT 0;

-- SQLite does not allow ADD COLUMN with UNIQUE inline; enforce uniqueness via
-- a partial unique index that ignores NULL values (the default for new rows).
CREATE UNIQUE INDEX IF NOT EXISTS apps_client_id_unique ON apps(client_id)
    WHERE client_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS oauth_codes (
    code         TEXT PRIMARY KEY,
    app_id       TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'openid',
    expires_at   DATETIME NOT NULL,
    used_at      DATETIME,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS oauth_codes_app_id     ON oauth_codes(app_id);
CREATE INDEX IF NOT EXISTS oauth_codes_expires_at ON oauth_codes(expires_at);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    token      TEXT PRIMARY KEY,
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes     TEXT NOT NULL DEFAULT 'openid',
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS oauth_tokens_app_id     ON oauth_tokens(app_id);
CREATE INDEX IF NOT EXISTS oauth_tokens_user_id    ON oauth_tokens(user_id);
CREATE INDEX IF NOT EXISTS oauth_tokens_expires_at ON oauth_tokens(expires_at);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token      TEXT PRIMARY KEY,
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scopes     TEXT NOT NULL DEFAULT 'openid',
    expires_at DATETIME NOT NULL,
    used_at    DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_app_id     ON oauth_refresh_tokens(app_id);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expires_at ON oauth_refresh_tokens(expires_at);

CREATE TABLE IF NOT EXISTS oidc_config (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oidc_config;
DROP INDEX IF EXISTS oauth_refresh_tokens_expires_at;
DROP INDEX IF EXISTS oauth_refresh_tokens_app_id;
DROP TABLE IF EXISTS oauth_refresh_tokens;
DROP INDEX IF EXISTS oauth_tokens_expires_at;
DROP INDEX IF EXISTS oauth_tokens_user_id;
DROP INDEX IF EXISTS oauth_tokens_app_id;
DROP TABLE IF EXISTS oauth_tokens;
DROP INDEX IF EXISTS oauth_codes_expires_at;
DROP INDEX IF EXISTS oauth_codes_app_id;
DROP TABLE IF EXISTS oauth_codes;
DROP INDEX IF EXISTS apps_client_id_unique;
-- SQLite does not support DROP COLUMN portably; leave added columns in place.
-- +goose StatementEnd
