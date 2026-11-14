package session_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// idleFixture builds a session service with the given idle window (minutes) and
// returns the store and user so tests can insert sessions with controlled
// timestamps.
func idleFixture(t *testing.T, idleMinutes int) (*session.Service, *session.SQLiteStore, *user.User) {
	t.Helper()

	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig()
	cfg.Session.IdleTimeoutMinutes = idleMinutes
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	store := session.NewStore(db)
	svc := session.NewService(store, userStore, nil, nil, cfg, slog.Default())

	ctx := context.Background()
	u, err := userSvc.Register(ctx, "idle_user", "idle@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return svc, store, u
}

// insertSession writes a session with explicit timestamps so the idle window
// can be exercised without sleeping.
func insertSession(t *testing.T, store *session.SQLiteStore, u *user.User, id string, created, lastUsed, expires time.Time) *session.Session {
	t.Helper()
	sess := &session.Session{
		ID:         id,
		PublicID:   "public-" + id,
		UserID:     u.ID,
		IPAddress:  "192.0.2.10",
		UserAgent:  "TestAgent/1.0",
		CreatedAt:  created,
		LastUsedAt: lastUsed,
		ExpiresAt:  expires,
	}
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatalf("insert session %q: %v", id, err)
	}
	return sess
}

// TestValidateSession_IdleExpired verifies that a session idle for longer than
// the configured window is rejected as expired and deleted.
func TestValidateSession_IdleExpired(t *testing.T) {
	t.Parallel()

	svc, store, u := idleFixture(t, 10) // 10-minute idle window
	ctx := context.Background()
	now := time.Now().UTC()

	// Created 2h ago, last used 30m ago (idle window 10m), absolute expiry
	// still 22h away.
	sess := insertSession(t, store, u, "idle-expired", now.Add(-2*time.Hour), now.Add(-30*time.Minute), now.Add(22*time.Hour))

	_, _, err := svc.ValidateSession(ctx, sess.ID)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Fatalf("ValidateSession: got %v, want ErrSessionExpired", err)
	}

	// The session must be gone, not merely refused.
	if _, err := store.GetByID(ctx, sess.ID); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("idle-expired session was not deleted: GetByID = %v, want ErrSessionNotFound", err)
	}
}

// TestValidateSession_IdleWithinWindow verifies that a recently-used session
// passes while the idle window is enabled.
func TestValidateSession_IdleWithinWindow(t *testing.T) {
	t.Parallel()

	svc, store, u := idleFixture(t, 10)
	ctx := context.Background()
	now := time.Now().UTC()

	sess := insertSession(t, store, u, "idle-fresh", now.Add(-2*time.Hour), now.Add(-2*time.Minute), now.Add(22*time.Hour))

	got, _, err := svc.ValidateSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("ValidateSession: unexpected error: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("ValidateSession: got session %q, want %q", got.ID, sess.ID)
	}
}

// TestValidateSession_IdleDisabled verifies that a zero idle window disables the
// idle check entirely: a session unused for days still passes as long as its
// absolute expiry has not passed.
func TestValidateSession_IdleDisabled(t *testing.T) {
	t.Parallel()

	svc, store, u := idleFixture(t, 0)
	ctx := context.Background()
	now := time.Now().UTC()

	sess := insertSession(t, store, u, "idle-off", now.Add(-72*time.Hour), now.Add(-72*time.Hour), now.Add(time.Hour))

	if _, _, err := svc.ValidateSession(ctx, sess.ID); err != nil {
		t.Fatalf("ValidateSession with idle disabled: unexpected error: %v", err)
	}
}

// TestValidateSession_IdleTouchesThrottled verifies that last_used_at is
// refreshed at most once per throttle window: a validation inside the window
// leaves the stored value untouched, one outside it advances it.
func TestValidateSession_IdleTouchesThrottled(t *testing.T) {
	t.Parallel()

	const idleMinutes = 60

	cases := []struct {
		name      string
		lastUsed  time.Duration // relative to now (negative = in the past)
		wantTouch bool
	}{
		{name: "inside throttle window", lastUsed: -2 * time.Minute, wantTouch: false},
		{name: "outside throttle window", lastUsed: -6 * time.Minute, wantTouch: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc, store, u := idleFixture(t, idleMinutes)
			ctx := context.Background()
			now := time.Now().UTC()

			sess := insertSession(t, store, u, "throttle-"+tc.name, now.Add(-2*time.Hour), now.Add(tc.lastUsed), now.Add(22*time.Hour))
			before, err := store.GetByID(ctx, sess.ID)
			if err != nil {
				t.Fatalf("GetByID before: %v", err)
			}

			if _, _, err := svc.ValidateSession(ctx, sess.ID); err != nil {
				t.Fatalf("ValidateSession: %v", err)
			}

			after, err := store.GetByID(ctx, sess.ID)
			if err != nil {
				t.Fatalf("GetByID after: %v", err)
			}

			advanced := after.LastUsedAt.Sub(before.LastUsedAt)
			if tc.wantTouch && advanced < time.Minute {
				t.Errorf("last_used_at was not refreshed: advanced by %v", advanced)
			}
			if !tc.wantTouch && advanced != 0 {
				t.Errorf("last_used_at was rewritten inside the throttle window: advanced by %v", advanced)
			}
		})
	}
}

// TestValidateSession_NullLastUsedFallsBackToCreated verifies the defensive
// handling of rows written before migration 018: a NULL last_used_at is judged
// against created_at.
func TestValidateSession_NullLastUsedFallsBackToCreated(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		created time.Duration // relative to now
		wantErr error         // nil = valid
	}{
		{name: "recent legacy row passes", created: -2 * time.Minute},
		{name: "old legacy row is idle", created: -30 * time.Minute, wantErr: session.ErrSessionExpired},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := testutil.NewTestDB(t)
			userStore := user.NewStore(db)
			cfg := testConfig()
			cfg.Session.IdleTimeoutMinutes = 10
			userSvc := user.NewService(userStore, userStore, nil, cfg)
			store := session.NewStore(db)
			svc := session.NewService(store, userStore, nil, nil, cfg, slog.Default())
			ctx := context.Background()

			u, err := userSvc.Register(ctx, "legacy_user", "legacy@example.com", "password123")
			if err != nil {
				t.Fatalf("Register: %v", err)
			}

			now := time.Now().UTC()
			created := now.Add(tc.created)
			const insertSQL = `INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
				VALUES ('legacy-token', 'legacy-public', ?, NULL, '', '', ?, ?)`
			if _, err := db.ExecContext(ctx, insertSQL, u.ID, now.Add(22*time.Hour), created); err != nil {
				t.Fatalf("insert legacy session: %v", err)
			}

			_, _, err = svc.ValidateSession(ctx, "legacy-token")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ValidateSession: got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateSession: unexpected error: %v", err)
			}
		})
	}
}

// TestSessionExpired nails the rule the user-facing sessions page shares with
// validation.
func TestSessionExpired(t *testing.T) {
	t.Parallel()

	svc, _, _ := idleFixture(t, 10)
	now := time.Now().UTC()

	cases := []struct {
		name       string
		expiresAt  time.Time
		lastUsedAt time.Time
		want       bool
	}{
		{name: "absolutely expired", expiresAt: now.Add(-time.Minute), lastUsedAt: now, want: true},
		{name: "idle", expiresAt: now.Add(time.Hour), lastUsedAt: now.Add(-11 * time.Minute), want: true},
		{name: "fresh", expiresAt: now.Add(time.Hour), lastUsedAt: now.Add(-time.Minute)},
		{name: "exactly at the window edge", expiresAt: now.Add(time.Hour), lastUsedAt: now.Add(-10 * time.Minute)},
		{name: "unknown last use falls back to created", expiresAt: now.Add(time.Hour), lastUsedAt: time.Time{}, want: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sess := &session.Session{
				ExpiresAt:  tc.expiresAt,
				CreatedAt:  now.Add(-time.Hour),
				LastUsedAt: tc.lastUsedAt,
			}
			if got := svc.SessionExpired(context.Background(), sess, now); got != tc.want {
				t.Errorf("SessionExpired = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTouchLastUsed_ConditionalGuard verifies the store-level throttle: the
// UPDATE only fires when the stored value is older than staleBefore, so a
// burst of requests cannot produce a burst of writes.
func TestTouchLastUsed_ConditionalGuard(t *testing.T) {
	t.Parallel()

	_, store, u := idleFixture(t, 0)
	ctx := context.Background()
	now := time.Now().UTC()

	sess := insertSession(t, store, u, "guard", now.Add(-time.Hour), now.Add(-10*time.Minute), now.Add(time.Hour))

	// First touch: the stored value (10m ago) is older than the 5m threshold.
	if err := store.TouchLastUsed(ctx, sess.ID, now, now.Add(-5*time.Minute)); err != nil {
		t.Fatalf("TouchLastUsed: %v", err)
	}
	first, err := store.GetByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !first.LastUsedAt.Equal(now) {
		t.Fatalf("last_used_at = %v, want %v", first.LastUsedAt, now)
	}

	// Second touch moments later: the stored value is now, so the guard skips
	// the write and the value must not move.
	if err := store.TouchLastUsed(ctx, sess.ID, now.Add(time.Minute), now.Add(-5*time.Minute)); err != nil {
		t.Fatalf("TouchLastUsed second: %v", err)
	}
	second, err := store.GetByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetByID second: %v", err)
	}
	if !second.LastUsedAt.Equal(first.LastUsedAt) {
		t.Errorf("guarded touch rewrote last_used_at: %v → %v", first.LastUsedAt, second.LastUsedAt)
	}
}

// TestDeleteIdleBefore verifies the periodic idle sweep: idle sessions go, fresh
// ones stay, and a NULL last_used_at is judged on created_at.
func TestDeleteIdleBefore(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig()
	userSvc := user.NewService(userStore, userStore, nil, cfg)
	store := session.NewStore(db)
	ctx := context.Background()

	u, err := userSvc.Register(ctx, "sweep_user", "sweep@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	now := time.Now().UTC()
	insertSession(t, store, u, "sweep-idle", now.Add(-3*time.Hour), now.Add(-2*time.Hour), now.Add(time.Hour))
	insertSession(t, store, u, "sweep-fresh", now.Add(-3*time.Hour), now.Add(-time.Minute), now.Add(time.Hour))
	// Legacy row: no last_used_at, created long ago.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sessions (id, public_id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		 VALUES ('sweep-legacy', 'sweep-legacy-public', ?, NULL, '', '', ?, ?)`,
		u.ID, now.Add(time.Hour), now.Add(-3*time.Hour),
	); err != nil {
		t.Fatalf("insert legacy session: %v", err)
	}

	if err := store.DeleteIdleBefore(ctx, now.Add(-time.Hour)); err != nil {
		t.Fatalf("DeleteIdleBefore: %v", err)
	}

	remaining, err := store.ListByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(remaining) != 1 || remaining[0].ID != "sweep-fresh" {
		var ids []string
		for _, s := range remaining {
			ids = append(ids, s.ID)
		}
		t.Errorf("remaining sessions = %v, want [sweep-fresh]", ids)
	}
}
