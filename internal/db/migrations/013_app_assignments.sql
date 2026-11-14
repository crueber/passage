-- +goose Up
-- +goose StatementBegin

-- Step two of groups/roles: assignment tables. All membership is flat —
-- users hold groups and roles directly; roles contain groups. A user's
-- effective groups are direct groups plus the groups of every role they
-- hold, resolved at read time (never stored per user).

-- Group assigned to a role: everyone holding the role effectively has the group.
CREATE TABLE IF NOT EXISTS app_role_groups (
    role_id    TEXT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
    group_id   TEXT NOT NULL REFERENCES app_groups(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, group_id)
);

CREATE INDEX IF NOT EXISTS app_role_groups_group_id ON app_role_groups(group_id);

-- Direct group assignment for a user within an app.
CREATE TABLE IF NOT EXISTS user_app_groups (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    group_id   TEXT NOT NULL REFERENCES app_groups(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, app_id, group_id)
);

CREATE INDEX IF NOT EXISTS user_app_groups_group_id ON user_app_groups(group_id);

-- Direct role assignment for a user within an app.
CREATE TABLE IF NOT EXISTS user_app_roles (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES app_roles(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, app_id, role_id)
);

CREATE INDEX IF NOT EXISTS user_app_roles_role_id ON user_app_roles(role_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_app_roles;
DROP TABLE IF EXISTS user_app_groups;
DROP TABLE IF EXISTS app_role_groups;
-- +goose StatementEnd
