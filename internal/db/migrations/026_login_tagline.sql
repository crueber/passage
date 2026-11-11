-- +goose Up
-- +goose StatementBegin

-- The line of text under the sign-in card. It is presentation copy, so it lives
-- in the settings store and is edited in the admin UI rather than the config
-- file. Seeding it with the text that used to be hard-coded in the templates
-- keeps every upgrade looking identical; clearing the field hides the line.
INSERT OR IGNORE INTO settings (key, value) VALUES
    ('login_tagline', 'Self-hosted authentication for your home lab');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM settings WHERE key = 'login_tagline';
-- +goose StatementEnd
