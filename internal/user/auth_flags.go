package user

import (
	"context"
	"strings"
)

// isAuthMethodEnabled reads a boolean feature flag from settings.
// Takes a settingsReader (already defined in handler.go in this package).
// Returns true if the key is absent (fail-open = method is enabled by default).
// Returns false only if the key is explicitly set to "false".
func isAuthMethodEnabled(ctx context.Context, r settingsReader, key string) bool {
	if r == nil {
		return true
	}
	val, err := r.Get(ctx, key)
	if err != nil {
		// Key not found or DB error: default to enabled.
		return true
	}
	return strings.ToLower(strings.TrimSpace(val)) != "false"
}

const (
	SettingPasswordEnabled  = "auth_password_enabled"
	SettingPasskeyEnabled   = "auth_passkey_enabled"
	SettingMagicLinkEnabled = "auth_magic_link_enabled"
)
