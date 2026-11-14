-- +goose Up
-- +goose StatementBegin

-- Per-app access policies.
--
-- Six new columns on apps, all additive with a "no restriction" default, so an
-- app registered before this migration behaves exactly as it did: empty strings
-- and admin_only = 0 mean the policy imposes nothing. No existing column is
-- altered and no row is rewritten.
--
--   required_group  one app-scoped group name the user must effectively hold
--   required_role   one app-scoped role name the user must hold
--   allowed_cidrs   comma/space separated CIDR prefixes (IPv4 or IPv6)
--   admin_only      1 = only admin users may use the app
--   allowed_hours   HH:MM-HH:MM in server local time; may wrap past midnight
--   allowed_days    ISO weekday list (1 = Monday … 7 = Sunday), ranges allowed
--
-- Parsing and evaluation live in internal/policy; the admin form validates the
-- text fields before saving so a malformed value never reaches this table.
ALTER TABLE apps ADD COLUMN required_group TEXT NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN required_role TEXT NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN allowed_cidrs TEXT NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN admin_only INTEGER NOT NULL DEFAULT 0;
ALTER TABLE apps ADD COLUMN allowed_hours TEXT NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN allowed_days TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE apps DROP COLUMN required_group;
ALTER TABLE apps DROP COLUMN required_role;
ALTER TABLE apps DROP COLUMN allowed_cidrs;
ALTER TABLE apps DROP COLUMN admin_only;
ALTER TABLE apps DROP COLUMN allowed_hours;
ALTER TABLE apps DROP COLUMN allowed_days;
-- +goose StatementEnd
