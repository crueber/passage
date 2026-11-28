package user

import (
	"context"

	"github.com/crueber/passage/internal/settings"
)

// isAuthMethodEnabled reads a boolean feature flag from settings, delegating
// to settings.Bool with a fail-open default of true.
func isAuthMethodEnabled(ctx context.Context, r settingsReader, key string) bool {
	return settings.Bool(ctx, r, key, true)
}

const (
	SettingPasswordEnabled  = settings.PasswordEnabled
	SettingPasskeyEnabled   = settings.PasskeyEnabled
	SettingMagicLinkEnabled = settings.MagicLinkEnabled
)
