-- +goose Up

CREATE TABLE magic_link_tokens (
    token       TEXT    NOT NULL PRIMARY KEY,
    user_id     TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX magic_link_tokens_user_id ON magic_link_tokens(user_id);
CREATE INDEX magic_link_tokens_expires_at ON magic_link_tokens(expires_at);

-- Seed the default magic link TTL setting.
INSERT OR IGNORE INTO settings (key, value) VALUES ('magic_link_ttl_minutes', '15');

-- +goose Down
DROP TABLE IF EXISTS magic_link_tokens;
DELETE FROM settings WHERE key = 'magic_link_ttl_minutes';
