-- +goose Up
-- +goose StatementBegin

-- OIDC signing keys with kid history.
--
-- Before this table, one RSA key lived in oidc_config under the key
-- 'rsa_private_key' and its kid was derived from the public key. That key is
-- still the single source of truth for an older binary, so the migration does
-- NOT move or delete it: at startup (oauth.EnsureSigningKeys) the legacy PEM is
-- imported here with its derived kid when this table is empty. A rollback to a
-- previous version therefore still finds its key, and an existing id_token
-- keeps verifying because the kid did not change.
--
-- Rotating a key inserts a new row and makes it current (newest created_at
-- wins). Older rows stay valid for verification and are still served in
-- /.well-known/jwks.json, which is what keeps live id_tokens verifiable until
-- they expire. retired_at is the tombstone: a retired key is neither served
-- nor accepted, and only retired rows may be deleted.
--
-- Additive only: nothing here alters an existing table, so an upgrade cannot
-- take authentication down. A database that never rotates behaves exactly as
-- it did before.
CREATE TABLE IF NOT EXISTS oauth_signing_keys (
    kid             TEXT PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at      DATETIME
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oauth_signing_keys;
-- +goose StatementEnd
