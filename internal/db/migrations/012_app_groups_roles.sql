-- +goose Up
-- +goose StatementBegin

-- App groups: named collections scoped to a single app. Step one of the
-- groups/roles feature — CRUD only; user assignment comes later.
CREATE TABLE IF NOT EXISTS app_groups (
    id          TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (app_id, name)
);

CREATE INDEX IF NOT EXISTS app_groups_app_id ON app_groups(app_id);

-- App roles: named roles scoped to a single app. Same shape and lifecycle
-- as groups.
CREATE TABLE IF NOT EXISTS app_roles (
    id          TEXT PRIMARY KEY,
    app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (app_id, name)
);

CREATE INDEX IF NOT EXISTS app_roles_app_id ON app_roles(app_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_roles;
DROP TABLE IF EXISTS app_groups;
-- +goose StatementEnd
