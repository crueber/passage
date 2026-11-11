-- +goose Up
-- +goose StatementBegin

-- OAuth scope registry, RFC 8707 resource indicators, and the JWT access-token
-- revocation denylist.
--
-- apps.scopes and apps.resources are the per-client registries, one value per
-- line. Empty means "no registry", which is exactly today's behaviour: the
-- client may ask for any scope and no resource indicator is accepted. An
-- upgrade therefore changes nothing for an app that never sets them.
--
-- oauth_codes.resource persists the audience granted at authorization time so
-- the token endpoint issues the access token for the resource the user
-- actually approved. Empty means the client did not request one and the token
-- audience is the client id, as before.
--
-- oauth_revoked_jti is the denylist that makes a stateless JWT access token
-- revocable (RFC 7009). A jti is inserted on revocation and consulted by
-- introspection and userinfo; the row is only needed until the token would
-- have expired anyway, so the hourly cleanup removes expired entries.
--
-- Additive only: no existing column is altered and no row is rewritten.
ALTER TABLE apps ADD COLUMN scopes    TEXT NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN resources TEXT NOT NULL DEFAULT '';

ALTER TABLE oauth_codes ADD COLUMN resource TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS oauth_revoked_jti (
    jti        TEXT PRIMARY KEY,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS oauth_revoked_jti_expires_at ON oauth_revoked_jti(expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS oauth_revoked_jti_expires_at;
DROP TABLE IF EXISTS oauth_revoked_jti;
ALTER TABLE oauth_codes DROP COLUMN resource;
ALTER TABLE apps DROP COLUMN resources;
ALTER TABLE apps DROP COLUMN scopes;
-- +goose StatementEnd
