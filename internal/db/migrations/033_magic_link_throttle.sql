-- +goose Up

-- magic_link_throttle tracks failed magic-link requests per client IP.
--
-- A row is only created when a request names an address with no account:
-- asking for a link to your own account is never recorded, so a person who
-- mistypes their address a couple of times is not penalised. Three failures
-- inside one 24-hour window lock the address for 24 hours.
CREATE TABLE IF NOT EXISTS magic_link_throttle (
    ip             TEXT NOT NULL PRIMARY KEY,
    failures       INTEGER NOT NULL DEFAULT 0,
    window_started DATETIME,
    locked_until   DATETIME,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_magic_link_throttle_locked
    ON magic_link_throttle (locked_until);

-- +goose Down
DROP INDEX IF EXISTS idx_magic_link_throttle_locked;
DROP TABLE IF EXISTS magic_link_throttle;
