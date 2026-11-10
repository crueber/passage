-- +goose Up
-- +goose StatementBegin

-- Refresh-token families for reuse detection (OAuth 2.1 §6.1): every refresh
-- token belongs to a family that starts at the initial code exchange and
-- continues through rotation. A replayed (already-used) token means the
-- credential leaked, so the whole family is revoked.
--
-- Additive and safe on a populated table: existing rows are backfilled with a
-- family of their own, which preserves today's behaviour (they are allowed to
-- rotate exactly once, as before).
ALTER TABLE oauth_refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT '';
UPDATE oauth_refresh_tokens SET family_id = token WHERE family_id = '';
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_family ON oauth_refresh_tokens(family_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS oauth_refresh_tokens_family;
-- SQLite 3.35+ (the version bundled with modernc.org/sqlite) can drop a column
-- directly; the index above must go first. Rolling back discards family
-- grouping only — token rows themselves are untouched.
ALTER TABLE oauth_refresh_tokens DROP COLUMN family_id;
-- +goose StatementEnd
