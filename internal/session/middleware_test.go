package session_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// TestRequireSession_RedirectsWithNoCookie verifies that a request without a
// session cookie is redirected to /login with the rd= query parameter.
func TestRequireSession_RedirectsWithNoCookie(t *testing.T) {
	t.Parallel()
	_, _, svc, _ := setup(t)
	cfg := testConfig()

	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("REACHED"))
	})

	handler := session.RequireSession(svc, cfg)(inner)

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected status 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("Location %q does not contain /login", loc)
	}
	if !strings.Contains(loc, "rd=") {
		t.Errorf("Location %q does not contain rd= param", loc)
	}
	if reached {
		t.Error("inner handler was reached; expected it to be skipped")
	}
}

// TestRequireSession_PassesWithValidSession verifies that a request with a
// valid session cookie reaches the inner handler and places the user in context.
func TestRequireSession_PassesWithValidSession(t *testing.T) {
	t.Parallel()
	_, _, svc, u := setup(t)
	cfg := testConfig()

	// Create a real session for the user.
	sess, err := svc.NewSession(context.Background(), u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxUser, ok := session.UserFromContext(r.Context())
		if !ok || ctxUser == nil {
			t.Error("UserFromContext: expected user in context, got none")
			http.Error(w, "no user", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("REACHED " + ctxUser.Username))
	})

	handler := session.RequireSession(svc, cfg)(inner)

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.Session.CookieName,
		Value: sess.ID,
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "REACHED") {
		t.Errorf("body %q does not contain REACHED", bodyStr)
	}
	if !strings.Contains(bodyStr, u.Username) {
		t.Errorf("body %q does not contain username %q", bodyStr, u.Username)
	}
}

// TestRequireSession_RedirectsWithExpiredSession verifies that a request with
// an expired session cookie is redirected to /login.
func TestRequireSession_RedirectsWithExpiredSession(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)

	userStore := user.NewStore(db)
	cfg := testConfig()
	userSvc := user.NewService(userStore, userStore, cfg)
	sessionStore := session.NewStore(db)
	svc := session.NewService(sessionStore, userStore, nil, cfg, slog.Default())

	ctx := context.Background()
	u, err := userSvc.Register(ctx, "expired_mw_user", "expiredmw@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Insert a session that already expired.
	pastExpiry := time.Now().UTC().Add(-1 * time.Hour)
	const insertSQL = `INSERT INTO sessions (id, user_id, app_id, ip_address, user_agent, expires_at, created_at)
		VALUES ('mw-expired-token', ?, NULL, '', '', ?, ?)`
	if _, err := db.ExecContext(ctx, insertSQL, u.ID, pastExpiry, time.Now().UTC()); err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("REACHED"))
	})

	handler := session.RequireSession(svc, cfg)(inner)

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.Session.CookieName,
		Value: "mw-expired-token",
	})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected status 302, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("Location %q does not contain /login", loc)
	}
}

// TestWithUser_AndUserFromContext verifies that WithUser stores a user in a
// context and UserFromContext retrieves the same user.
func TestWithUser_AndUserFromContext(t *testing.T) {
	t.Parallel()
	u := &user.User{
		ID:       "test-user-id",
		Username: "testuser",
		IsActive: true,
	}

	ctx := session.WithUser(context.Background(), u)
	got, ok := session.UserFromContext(ctx)

	if !ok {
		t.Fatal("UserFromContext: expected ok=true, got false")
	}
	if got == nil {
		t.Fatal("UserFromContext: expected non-nil user, got nil")
	}
	if got.ID != u.ID {
		t.Errorf("UserFromContext: got ID %q, want %q", got.ID, u.ID)
	}
}

// TestUserFromContext_Missing verifies that UserFromContext returns nil, false
// when no user has been stored in the context.
func TestUserFromContext_Missing(t *testing.T) {
	t.Parallel()
	got, ok := session.UserFromContext(context.Background())

	if ok {
		t.Error("UserFromContext: expected ok=false, got true")
	}
	if got != nil {
		t.Errorf("UserFromContext: expected nil user, got %v", got)
	}
}
