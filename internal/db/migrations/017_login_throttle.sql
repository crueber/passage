-- +goose Up
-- +goose StatementBegin

-- Per-account password-login throttling. Keyed by the lowercased username so
-- an unknown username is throttled exactly like a real one: the page must not
-- become a faster account-existence oracle than guessing.
--
-- This table is deliberately standalone. There is no foreign key to users —
-- unknown usernames have no row, and deleting a user must not leave a lock
-- that can never be cleared.
CREATE TABLE IF NOT EXISTS login_throttle (
    username     TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until DATETIME,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Admin list rendering and expiry lookups scan for currently locked rows.
CREATE INDEX IF NOT EXISTS login_throttle_locked_until ON login_throttle(locked_until);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS login_throttle_locked_until;
DROP TABLE IF EXISTS login_throttle;
-- +goose StatementEnd
