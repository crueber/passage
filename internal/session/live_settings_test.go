package session_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// liveSettings is a minimal settings reader for the idle-timeout tests.
type liveSettings map[string]string

func (m liveSettings) Get(_ context.Context, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", errors.New("setting not found")
	}
	return v, nil
}

// TestValidateSession_IdleTimeoutIsLive proves an idle-window change in the
// settings table applies without rebuilding the session service.
func TestValidateSession_IdleTimeoutIsLive(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig()
	cfg.Session.IdleTimeoutMinutes = 0 // startup snapshot: disabled
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	store := session.NewStore(db)
	live := liveSettings{settings.SessionIdleTimeoutMinutes: "10"}
	svc := session.NewService(store, userStore, live, nil, cfg, slog.Default())

	ctx := context.Background()
	u, err := userSvc.Register(ctx, "live_idle", "live-idle@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	now := time.Now().UTC()
	idle := insertSession(t, store, u, "live-idle", now.Add(-2*time.Hour), now.Add(-30*time.Minute), now.Add(22*time.Hour))
	if _, _, err := svc.ValidateSession(ctx, idle.ID); !errors.Is(err, session.ErrSessionExpired) {
		t.Fatalf("with a live 10-minute window: got %v, want ErrSessionExpired", err)
	}

	// Turning the window off must apply just as immediately.
	live[settings.SessionIdleTimeoutMinutes] = "0"
	fresh := insertSession(t, store, u, "live-idle-off", now.Add(-2*time.Hour), now.Add(-30*time.Minute), now.Add(22*time.Hour))
	if _, _, err := svc.ValidateSession(ctx, fresh.ID); err != nil {
		t.Fatalf("with a live disabled window: got %v, want a valid session", err)
	}
}
