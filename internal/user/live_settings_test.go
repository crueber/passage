package user_test

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// TestService_LivePasswordAndMailSettings proves the two constructor-era values
// follow the settings table: the bcrypt cost and whether SMTP is usable.
func TestService_LivePasswordAndMailSettings(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	store := user.NewStore(db)
	cfg := testConfig(true) // cost 10, no SMTP in the startup snapshot
	svc := user.NewService(store, store, nil, cfg)
	live := &fixtureSettings{values: map[string]string{
		settings.BcryptCost: "11",
		settings.SMTPHost:   "smtp.example.com",
		settings.SMTPFrom:   "passage@example.com",
	}}
	svc.SetSettings(live)
	ctx := context.Background()

	u, err := svc.Register(ctx, "live_settings", "live-settings@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(u.PasswordHash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != 11 {
		t.Errorf("hash cost = %d, want the live setting 11", cost)
	}
	if u.EmailVerified {
		t.Error("registration marked verified while live SMTP is configured")
	}

	// Clearing the SMTP settings must disable mail immediately, not fall back to
	// the startup snapshot.
	live.values[settings.SMTPHost] = ""
	live.values[settings.SMTPFrom] = ""
	u2, err := svc.Register(ctx, "live_settings_2", "live-settings-2@example.com", "password123")
	if err != nil {
		t.Fatalf("Register second: %v", err)
	}
	if !u2.EmailVerified {
		t.Error("registration is unverified after SMTP was removed")
	}
}
