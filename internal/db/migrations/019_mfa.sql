-- +goose Up
-- +goose StatementBegin

-- Two-factor authentication (TOTP + single-use recovery codes).
--
-- Three new tables, all additive: nothing here alters an existing table, so an
-- upgrade can never take authentication down. A database that has no rows in
-- any of these tables behaves exactly as it did before the feature existed.
--
-- user_mfa holds the TOTP secret as base32 (no padding). The secret is not
-- encrypted: the SQLite file is expected to be mode 0600 (docs/security.md).
-- enabled_at NULL means "enrollment started but never verified", which is not
-- enforced at login — an abandoned enrollment must not lock anyone out.
-- last_step is the highest accepted TOTP counter, the anti-replay watermark.
CREATE TABLE IF NOT EXISTS user_mfa (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret     TEXT NOT NULL,
    last_step  INTEGER NOT NULL DEFAULT 0,
    enabled_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Recovery codes are stored only as hex sha256 of the normalised code. used_at
-- is set by a conditional UPDATE (WHERE used_at IS NULL), which is what makes a
-- code single-use even under concurrent requests.
CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash       TEXT NOT NULL,
    used_at    DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, hash)
);

-- A pending second factor after a correct password. This is NOT a session:
-- RequireSession never reads this table, and no privilege is granted until a
-- code is verified. The row is deleted on success or expiry.
CREATE TABLE IF NOT EXISTS mfa_challenges (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    return_to  TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS mfa_challenges_user_id ON mfa_challenges(user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS mfa_challenges_user_id;
DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS user_mfa_recovery_codes;
DROP TABLE IF EXISTS user_mfa;
-- +goose StatementEnd
