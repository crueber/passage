-- +goose Up
-- +goose StatementBegin

-- Authentication events: logins, logouts, passkey and magic-link use, and
-- their failures. This is an append-only log with no foreign key to users —
-- a failed login for an unknown username has no user row, and deleting a user
-- must not silently delete their authentication history. Names are resolved
-- from user_id at read time when needed.
CREATE TABLE IF NOT EXISTS auth_events (
    id         TEXT PRIMARY KEY,
    event      TEXT NOT NULL,
    outcome    TEXT NOT NULL DEFAULT '',
    user_id    TEXT NOT NULL DEFAULT '',
    username   TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS auth_events_created_at ON auth_events(created_at);
CREATE INDEX IF NOT EXISTS auth_events_event      ON auth_events(event);
CREATE INDEX IF NOT EXISTS auth_events_user_id    ON auth_events(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS auth_events_user_id;
DROP INDEX IF EXISTS auth_events_event;
DROP INDEX IF EXISTS auth_events_created_at;
DROP TABLE IF EXISTS auth_events;
-- +goose StatementEnd
