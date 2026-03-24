package session_test

import (
	"context"
	"errors"
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
	sessionSvc = session.NewService(sessionStore, userStore, cfg, slog.Default())

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
	sessionSvc := session.NewService(sessionStore, userStore, &expiredCfg, slog.Default())

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
	sessionSvc := session.NewService(sessionStore, userStore, cfg, slog.Default())
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
