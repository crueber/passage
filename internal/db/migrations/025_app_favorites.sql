-- +goose Up
-- +goose StatementBegin

-- Per-user dashboard pin ("favourite"). Additive: the default of 0 means every
-- existing access row keeps the plain name-ordered dashboard, and the column is
-- written only when someone taps the star.
--
-- This lives on user_app_access rather than apps because a pin is personal: the
-- same app is pinned by one user and not another. Losing access removes the row
-- (and with it the pin), which is the intended behaviour.
ALTER TABLE user_app_access ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- SQLite cannot drop a column without rebuilding the table; the column is
-- harmless if left in place after a downgrade.
-- +goose StatementEnd
