-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id           TEXT PRIMARY KEY,
    session_data TEXT NOT NULL,
    expires_at   DATETIME NOT NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS webauthn_challenges_expires_at ON webauthn_challenges(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS webauthn_challenges_expires_at;
DROP TABLE IF EXISTS webauthn_challenges;
-- +goose StatementEnd
