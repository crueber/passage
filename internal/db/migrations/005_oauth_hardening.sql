-- +goose Up
-- +goose StatementBegin
ALTER TABLE oauth_codes ADD COLUMN nonce TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_codes ADD COLUMN auth_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite does not support DROP COLUMN in older versions; migration is not reversible
-- +goose StatementEnd
