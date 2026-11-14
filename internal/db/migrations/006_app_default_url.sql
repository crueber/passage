-- +goose Up
-- +goose StatementBegin
ALTER TABLE apps ADD COLUMN default_url TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite does not support DROP COLUMN portably; migration is not reversible.
-- +goose StatementEnd
