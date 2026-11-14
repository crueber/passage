-- +goose Up

-- Seed auth method feature flags.
-- Defaults: password and passkey enabled; magic link disabled.
INSERT OR IGNORE INTO settings (key, value) VALUES ('auth_password_enabled',  'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('auth_passkey_enabled',   'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('auth_magic_link_enabled', 'false');

-- +goose Down
DELETE FROM settings WHERE key IN (
    'auth_password_enabled',
    'auth_passkey_enabled',
    'auth_magic_link_enabled'
);
