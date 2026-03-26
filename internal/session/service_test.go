package session_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// testConfig returns a minimal Config for session tests.
func testConfig() *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			AllowRegistration: true,
			BcryptCost:        10,
		},
		Session: config.SessionConfig{
			DurationHours: 24,
			CookieName:    "passage_session",
			CookieSecure:  false,
		},
	}
}

// setup creates a real in-memory DB with stores and services for both user and
// session packages. Returns a registered active user for convenience.
func setup(t *testing.T) (userSvc *user.Service, userStore *user.SQLiteStore, sessionSvc *session.Service, activeUser *user.User) {
	t.Helper()
	db := testutil.NewTestDB(t)
	userStore = user.NewStore(db)
	cfg := testConfig()
	userSvc = user.NewService(userStore, userStore, cfg)

	sessionStore := session.NewStore(db)
	// nil settings: fall back to cfg.Session.DurationHours (24h).
	sessionSvc = session.NewService(sessionStore, userStore, nil, cfg, slog.Default())

	ctx := context.Background()
	u, err := userSvc.Register(ctx, "tester", "tester@example.com", "password123")
	if err != nil {
		t.Fatalf("setup: Register: %v", err)
	}
	return userSvc, userStore, sessionSvc, u
}

// TestNewSession verifies that a session is created with a non-empty token and
// the correct user ID and expiry in the future.
func TestNewSession(t *testing.T) {
	t.Parallel()
	_, _, svc, u := setup(t)
	ctx := context.Background()

	sess, err := svc.NewSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession: unexpected error: %v", err)
	}
	if sess.ID == "" {
		t.Error("NewSession: expected non-empty ID")
	}
	if sess.UserID != u.ID {
		t.Errorf("NewSession: got UserID %q, want %q", sess.UserID, u.ID)
	}
	if sess.AppID != nil {
		t.Errorf("NewSession: expected nil AppID, got %v", *sess.AppID)
	}
	if !sess.ExpiresAt.After(time.Now()) {
		t.Errorf("NewSession: ExpiresAt %v is not in the future", sess.ExpiresAt)
	}
}

// TestCreateSession verifies the primitive-returning wrapper used by the
// user.Handler to break the import cycle.
func TestCreateSession(t *testing.T) {
	t.Parallel()
	_, _, svc, u := setup(t)
	ctx := context.Background()

	token, expiresAt, err := svc.CreateSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("CreateSession: unexpected error: %v", err)
	}
	if token == "" {
		t.Error("CreateSession: expected non-empty token")
	}
	if !expiresAt.After(time.Now()) {
		t.Errorf("CreateSession: expiresAt %v is not in the future", expiresAt)
	}
}

// TestValidateSession verifies that a valid session returns the expected session
// and user.
func TestValidateSession(t *testing.T) {
	t.Parallel()
	_, _, svc, u := setup(t)
	ctx := context.Background()

	sess, err := svc.NewSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	gotSess, gotUser, err := svc.ValidateSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("ValidateSession: unexpected error: %v", err)
	}
	if gotSess.ID != sess.ID {
		t.Errorf("ValidateSession: got session ID %q, want %q", gotSess.ID, sess.ID)
	}
	if gotUser.ID != u.ID {
		t.Errorf("ValidateSession: got user ID %q, want %q", gotUser.ID, u.ID)
	}
}

// TestValidateSession_NotFound verifies that a non-existent token returns a
// wrapped ErrSessionNotFound.
func TestValidateSession_NotFound(t *testing.T) {
	t.Parallel()
	_, _, svc, _ := setup(t)
	ctx := context.Background()

	_, _, err := svc.ValidateSession(ctx, "no-such-token")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("missing token: got %v, want ErrSessionNotFound", err)
	}
}

// TestValidateSession_Expired verifies that an expired session returns
// ErrSessionExpired.
func TestValidateSession_Expired(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig()
	userSvc := user.NewService(userStore, userStore, cfg)
	sessionStore := session.NewStore(db)

	// Use a 0-hour duration so sessions expire immediately.
	expiredCfg := *cfg
	expiredCfg.Session.DurationHours = 0
	sessionSvc := session.NewService(sessionStore, userStore, nil, &expiredCfg, slog.Default())

	ctx := context.Background()
	u, err := userSvc.Register(ctx, "expiry_user", "expiry@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Create a session that expires in the past by inserting it directly.
	pastExpiry := time.Now().UTC().Add(-1 * time.Hour)
	const insertSQL = `INSERT INTO sessions (id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		VALUES ('expired-token', ?, NULL, '', '', ?, ?)`
	if _, err := db.ExecContext(ctx, insertSQL, u.ID, pastExpiry, time.Now().UTC()); err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	_, _, err = sessionSvc.ValidateSession(ctx, "expired-token")
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("expired session: got %v, want ErrSessionExpired", err)
	}
}

// TestValidateSession_InactiveUser verifies that a valid session for an
// inactive user returns ErrUserInactive.
func TestValidateSession_InactiveUser(t *testing.T) {
	t.Parallel()
	_, userStore, svc, u := setup(t)
	ctx := context.Background()

	sess, err := svc.NewSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Deactivate the user.
	u.IsActive = false
	if err := userStore.Update(ctx, u); err != nil {
		t.Fatalf("Update (deactivate): %v", err)
	}

	_, _, err = svc.ValidateSession(ctx, sess.ID)
	if !errors.Is(err, user.ErrUserInactive) {
		t.Errorf("inactive user: got %v, want ErrUserInactive", err)
	}
}

// TestRevokeSession verifies that a revoked session can no longer be validated.
func TestRevokeSession(t *testing.T) {
	t.Parallel()
	_, _, svc, u := setup(t)
	ctx := context.Background()

	sess, err := svc.NewSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	if err := svc.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatalf("RevokeSession: unexpected error: %v", err)
	}

	_, _, err = svc.ValidateSession(ctx, sess.ID)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("revoked session: got %v, want ErrSessionNotFound", err)
	}
}

// TestListByUser verifies that ListByUser returns only sessions belonging to
// the requested user. Creates 2 sessions for user A and 1 for user B, then
// asserts exactly 2 are returned for user A.
func TestListByUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig()
	userSvc := user.NewService(userStore, userStore, cfg)
	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, cfg, slog.Default())
	ctx := context.Background()

	// Register two distinct users.
	userA, err := userSvc.Register(ctx, "list_user_a", "list_a@example.com", "password123")
	if err != nil {
		t.Fatalf("Register userA: %v", err)
	}
	userB, err := userSvc.Register(ctx, "list_user_b", "list_b@example.com", "password123")
	if err != nil {
		t.Fatalf("Register userB: %v", err)
	}

	// Create 2 sessions for userA.
	if _, err := sessionSvc.NewSession(ctx, userA.ID, nil, "10.0.0.1", "AgentA/1"); err != nil {
		t.Fatalf("NewSession A1: %v", err)
	}
	if _, err := sessionSvc.NewSession(ctx, userA.ID, nil, "10.0.0.2", "AgentA/2"); err != nil {
		t.Fatalf("NewSession A2: %v", err)
	}

	// Create 1 session for userB.
	if _, err := sessionSvc.NewSession(ctx, userB.ID, nil, "10.0.0.3", "AgentB/1"); err != nil {
		t.Fatalf("NewSession B1: %v", err)
	}

	got, err := sessionSvc.ListByUser(ctx, userA.ID)
	if err != nil {
		t.Fatalf("ListByUser: unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListByUser: got %d sessions, want 2", len(got))
	}
	for _, s := range got {
		if s.UserID != userA.ID {
			t.Errorf("ListByUser: got session with UserID %q, want %q", s.UserID, userA.ID)
		}
	}
}

// TestNewSession_NilAppID verifies that a session with nil AppID round-trips
// correctly through the store — the AppID field stays nil after ValidateSession.
func TestNewSession_NilAppID(t *testing.T) {
	t.Parallel()
	_, _, svc, u := setup(t)
	ctx := context.Background()

	sess, err := svc.NewSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession with nil AppID: %v", err)
	}

	got, _, err := svc.ValidateSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if got.AppID != nil {
		t.Errorf("ValidateSession: expected nil AppID, got %v", *got.AppID)
	}
}

// ─── Phase 4 new tests ────────────────────────────────────────────────────────

// stubSettings is a minimal in-memory settingsReader for tests.
type stubSettings struct {
	data map[string]string
}

func (s *stubSettings) Get(_ context.Context, key string) (string, error) {
	v, ok := s.data[key]
	if !ok {
		return "", fmt.Errorf("setting not found: %s", key)
	}
	return v, nil
}

// TestNewSession_UsesDurationFromDB verifies that when the settings store
// returns a valid "session_duration_hours" value, that value is used instead
// of cfg.Session.DurationHours.
func TestNewSession_UsesDurationFromDB(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig() // DurationHours = 24
	userSvc := user.NewService(userStore, userStore, cfg)

	// DB setting overrides config: 48 hours.
	settings := &stubSettings{data: map[string]string{"session_duration_hours": "48"}}
	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, settings, cfg, slog.Default())

	ctx := context.Background()
	u, err := userSvc.Register(ctx, "db_duration_user", "dbdur@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	sess, err := sessionSvc.NewSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// ExpiresAt should be approximately 48h from now (allow 5 minutes of slop).
	want := time.Now().Add(48 * time.Hour)
	diff := sess.ExpiresAt.Sub(want)
	if diff < -5*time.Minute || diff > 5*time.Minute {
		t.Errorf("NewSession: ExpiresAt %v is not ~48h from now (want %v)", sess.ExpiresAt, want)
	}
}

// TestNewSession_FallsBackToConfig verifies that when the settings store
// returns an error (key absent), the cfg.Session.DurationHours value is used.
func TestNewSession_FallsBackToConfig(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig() // DurationHours = 24
	userSvc := user.NewService(userStore, userStore, cfg)

	// Settings store has no "session_duration_hours" key.
	settings := &stubSettings{data: map[string]string{}}
	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, settings, cfg, slog.Default())

	ctx := context.Background()
	u, err := userSvc.Register(ctx, "fallback_user", "fallback@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	sess, err := sessionSvc.NewSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// ExpiresAt should be approximately 24h from now (allow 5 minutes of slop).
	want := time.Now().Add(24 * time.Hour)
	diff := sess.ExpiresAt.Sub(want)
	if diff < -5*time.Minute || diff > 5*time.Minute {
		t.Errorf("NewSession: ExpiresAt %v is not ~24h from now (want %v)", sess.ExpiresAt, want)
	}
}

// TestDeleteByUser verifies that DeleteByUser removes all sessions for a user
// but leaves sessions for other users intact.
func TestDeleteByUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig()
	userSvc := user.NewService(userStore, userStore, cfg)
	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, cfg, slog.Default())
	ctx := context.Background()

	userA, err := userSvc.Register(ctx, "del_user_a", "del_a@example.com", "password123")
	if err != nil {
		t.Fatalf("Register userA: %v", err)
	}
	userB, err := userSvc.Register(ctx, "del_user_b", "del_b@example.com", "password123")
	if err != nil {
		t.Fatalf("Register userB: %v", err)
	}

	// Create sessions for both users.
	if _, err := sessionSvc.NewSession(ctx, userA.ID, nil, "10.0.0.1", "AgentA/1"); err != nil {
		t.Fatalf("NewSession A1: %v", err)
	}
	if _, err := sessionSvc.NewSession(ctx, userA.ID, nil, "10.0.0.2", "AgentA/2"); err != nil {
		t.Fatalf("NewSession A2: %v", err)
	}
	if _, err := sessionSvc.NewSession(ctx, userB.ID, nil, "10.0.0.3", "AgentB/1"); err != nil {
		t.Fatalf("NewSession B1: %v", err)
	}

	// Delete all sessions for userA via the store directly.
	if err := sessionStore.DeleteByUser(ctx, userA.ID); err != nil {
		t.Fatalf("DeleteByUser: unexpected error: %v", err)
	}

	// userA should have no sessions.
	gotA, err := sessionSvc.ListByUser(ctx, userA.ID)
	if err != nil {
		t.Fatalf("ListByUser A: %v", err)
	}
	if len(gotA) != 0 {
		t.Errorf("after DeleteByUser: expected 0 sessions for userA, got %d", len(gotA))
	}

	// userB's session must be untouched.
	gotB, err := sessionSvc.ListByUser(ctx, userB.ID)
	if err != nil {
		t.Fatalf("ListByUser B: %v", err)
	}
	if len(gotB) != 1 {
		t.Errorf("after DeleteByUser: expected 1 session for userB, got %d", len(gotB))
	}
}

// TestRevokeAllByUser verifies the service-layer RevokeAllByUser method removes
// all sessions for the user and leaves other users' sessions intact.
func TestRevokeAllByUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	userStore := user.NewStore(db)
	cfg := testConfig()
	userSvc := user.NewService(userStore, userStore, cfg)
	sessionStore := session.NewStore(db)
	sessionSvc := session.NewService(sessionStore, userStore, nil, cfg, slog.Default())
	ctx := context.Background()

	userA, err := userSvc.Register(ctx, "revall_user_a", "revall_a@example.com", "password123")
	if err != nil {
		t.Fatalf("Register userA: %v", err)
	}
	userB, err := userSvc.Register(ctx, "revall_user_b", "revall_b@example.com", "password123")
	if err != nil {
		t.Fatalf("Register userB: %v", err)
	}

	if _, err := sessionSvc.NewSession(ctx, userA.ID, nil, "10.0.0.1", "AgentA/1"); err != nil {
		t.Fatalf("NewSession A1: %v", err)
	}
	if _, err := sessionSvc.NewSession(ctx, userA.ID, nil, "10.0.0.2", "AgentA/2"); err != nil {
		t.Fatalf("NewSession A2: %v", err)
	}
	if _, err := sessionSvc.NewSession(ctx, userB.ID, nil, "10.0.0.3", "AgentB/1"); err != nil {
		t.Fatalf("NewSession B1: %v", err)
	}

	if err := sessionSvc.RevokeAllByUser(ctx, userA.ID); err != nil {
		t.Fatalf("RevokeAllByUser: unexpected error: %v", err)
	}

	// userA should have no sessions.
	gotA, err := sessionSvc.ListByUser(ctx, userA.ID)
	if err != nil {
		t.Fatalf("ListByUser A: %v", err)
	}
	if len(gotA) != 0 {
		t.Errorf("after RevokeAllByUser: expected 0 sessions for userA, got %d", len(gotA))
	}

	// userB's session must be untouched.
	gotB, err := sessionSvc.ListByUser(ctx, userB.ID)
	if err != nil {
		t.Fatalf("ListByUser B: %v", err)
	}
	if len(gotB) != 1 {
		t.Errorf("after RevokeAllByUser: expected 1 session for userB, got %d", len(gotB))
	}
}
