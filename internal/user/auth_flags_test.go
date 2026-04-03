package user

import (
	"context"
	"errors"
	"testing"
)

// stubSettings is a test-only settingsReader that returns a fixed value or error.
type stubSettings struct {
	val string
	err error
}

func (s stubSettings) Get(_ context.Context, _ string) (string, error) {
	return s.val, s.err
}

func TestIsAuthMethodEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		settings settingsReader
		key      string
		want     bool
	}{
		{
			name:     "nil settings returns true (fail-open)",
			settings: nil,
			key:      SettingPasswordEnabled,
			want:     true,
		},
		{
			name:     "key not found returns true (fail-open)",
			settings: stubSettings{err: errors.New("not found")},
			key:      SettingPasswordEnabled,
			want:     true,
		},
		{
			name:     "value true returns true",
			settings: stubSettings{val: "true"},
			key:      SettingPasswordEnabled,
			want:     true,
		},
		{
			name:     "value True (mixed case) returns true",
			settings: stubSettings{val: "True"},
			key:      SettingPasswordEnabled,
			want:     true,
		},
		{
			name:     "value false returns false",
			settings: stubSettings{val: "false"},
			key:      SettingPasswordEnabled,
			want:     false,
		},
		{
			name:     "value FALSE (upper case) returns false",
			settings: stubSettings{val: "FALSE"},
			key:      SettingPasswordEnabled,
			want:     false,
		},
		{
			name:     "value False with whitespace returns false",
			settings: stubSettings{val: "  false  "},
			key:      SettingPasswordEnabled,
			want:     false,
		},
		{
			name:     "empty string returns true (not explicitly false)",
			settings: stubSettings{val: ""},
			key:      SettingPasswordEnabled,
			want:     true,
		},
		{
			name:     "passkey key with false returns false",
			settings: stubSettings{val: "false"},
			key:      SettingPasskeyEnabled,
			want:     false,
		},
		{
			name:     "magic link key with true returns true",
			settings: stubSettings{val: "true"},
			key:      SettingMagicLinkEnabled,
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isAuthMethodEnabled(context.Background(), tc.settings, tc.key)
			if got != tc.want {
				t.Errorf("isAuthMethodEnabled(%q) = %v, want %v", tc.key, got, tc.want)
			}
		})
	}
}
