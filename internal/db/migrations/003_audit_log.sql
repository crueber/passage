-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    actor_id    TEXT NOT NULL REFERENCES users(id),
    actor_name  TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    target_name TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    ip_address  TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS audit_log_actor_id   ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS audit_log_action     ON audit_log(action);
CREATE INDEX IF NOT EXISTS audit_log_created_at ON audit_log(created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS audit_log_created_at;
DROP INDEX IF EXISTS audit_log_action;
DROP INDEX IF EXISTS audit_log_actor_id;
DROP TABLE IF EXISTS audit_log;
-- +goose StatementEnd
