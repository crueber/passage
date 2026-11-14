-- +goose Up
-- +goose StatementBegin

-- Seed every UI-managed setting with its built-in default. INSERT OR
-- IGNORE leaves any value an operator already has (or that an earlier
-- migration created) untouched, so an upgrade changes no behaviour.
INSERT OR IGNORE INTO settings (key, value) VALUES
	('allow_registration', 'true'),
	('session_duration_hours', '24'),
	('session_idle_timeout_minutes', '0'),
	('auth_password_enabled', 'true'),
	('auth_passkey_enabled', 'true'),
	('auth_magic_link_enabled', 'false'),
	('magic_link_ttl_minutes', '15'),
	('auth_require_mfa', 'false'),
	('auth_max_login_failures', '5'),
	('auth_lockout_minutes', '15'),
	('auth_bcrypt_cost', '12'),
	('login_tagline', 'Self-hosted authentication for your home lab'),
	('login_header_phrase', ''),
	('login_header_style', 'for'),
	('ui_theme', 'slate'),
	('smtp_host', ''),
	('smtp_port', '587'),
	('smtp_username', ''),
	('smtp_password', ''),
	('smtp_tls', 'starttls'),
	('smtp_from', ''),
	('webhook_url', ''),
	('webhook_secret', ''),
	('webhook_timeout_seconds', '5'),
	('metrics_enabled', 'true'),
	('metrics_token', ''),
	('rate_limit_login_requests', '10'),
	('rate_limit_login_window_minutes', '15'),
	('rate_limit_register_requests', '10'),
	('rate_limit_register_window_minutes', '60'),
	('rate_limit_reset_requests', '5'),
	('rate_limit_reset_window_minutes', '60'),
	('rate_limit_magic_link_requests', '5'),
	('rate_limit_magic_link_window_minutes', '60'),
	('rate_limit_oauth_token_requests', '20'),
	('rate_limit_oauth_token_window_minutes', '1'),
	('rate_limit_setup_requests', '5'),
	('rate_limit_setup_window_minutes', '60');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Settings are operator data; a downgrade keeps them.
-- +goose StatementEnd
