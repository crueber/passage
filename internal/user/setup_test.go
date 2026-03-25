package user_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// ─── SetupTokenManager tests ─────────────────────────────────────────────────

func TestSetupTokenManager_NewSetupTokenManager(t *testing.T) {
	t.Parallel()
	mgr, token, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: unexpected error: %v", err)
	}
	if mgr == nil {
		t.Fatal("NewSetupTokenManager: expected non-nil manager")
	}
	if len(token) != 64 {
		t.Errorf("NewSetupTokenManager: expected 64-char hex token, got %d chars", len(token))
	}
}

func TestSetupTokenManager_IsActive(t *testing.T) {
	t.Parallel()
	mgr, _, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: %v", err)
	}
	if !mgr.IsActive() {
		t.Error("IsActive: expected true for a freshly created token")
	}
}

func TestSetupTokenManager_Consume_Valid(t *testing.T) {
	t.Parallel()
	mgr, token, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: %v", err)
	}

	if !mgr.Consume(token) {
		t.Error("Consume: expected true for valid token")
	}
}

func TestSetupTokenManager_Consume_SingleUse(t *testing.T) {
	t.Parallel()
	mgr, token, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: %v", err)
	}

	mgr.Consume(token) // first use

	if mgr.Consume(token) {
		t.Error("Consume: expected false on second use of same token")
	}
	if mgr.IsActive() {
		t.Error("IsActive: expected false after token has been consumed")
	}
}

func TestSetupTokenManager_Consume_WrongToken(t *testing.T) {
	t.Parallel()
	mgr, _, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: %v", err)
	}

	if mgr.Consume("wrong-token") {
		t.Error("Consume: expected false for wrong token")
	}
	// Manager should still be active after wrong-token attempt.
	if !mgr.IsActive() {
		t.Error("IsActive: expected true after failed consume attempt")
	}
}

func TestSetupTokenManager_Nil_IsNotActive(t *testing.T) {
	t.Parallel()
	var mgr *user.SetupTokenManager // nil
	if mgr.IsActive() {
		t.Error("IsActive on nil manager: expected false")
	}
	if mgr.Consume("any") {
		t.Error("Consume on nil manager: expected false")
	}
}

// ─── HasAdmin store tests ─────────────────────────────────────────────────────

func TestStore_HasAdmin_NoUsers(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)

	has, err := store.HasAdmin(context.Background())
	if err != nil {
		t.Fatalf("HasAdmin: unexpected error: %v", err)
	}
	if has {
		t.Error("HasAdmin: expected false when no users exist")
	}
}

func TestStore_HasAdmin_NonAdminUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)

	u := &user.User{
		Username:     "alice",
		Email:        "alice@example.com",
		PasswordHash: "hash",
		IsAdmin:      false,
		IsActive:     true,
		Roles:        "[]",
	}
	if err := store.Create(context.Background(), u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	has, err := store.HasAdmin(context.Background())
	if err != nil {
		t.Fatalf("HasAdmin: unexpected error: %v", err)
	}
	if has {
		t.Error("HasAdmin: expected false when only non-admin users exist")
	}
}

func TestStore_HasAdmin_WithAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	store := user.NewStore(db)

	u := &user.User{
		Username:     "admin",
		Email:        "admin@example.com",
		PasswordHash: "hash",
		IsAdmin:      true,
		IsActive:     true,
		Roles:        "[]",
	}
	if err := store.Create(context.Background(), u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	has, err := store.HasAdmin(context.Background())
	if err != nil {
		t.Fatalf("HasAdmin: unexpected error: %v", err)
	}
	if !has {
		t.Error("HasAdmin: expected true when admin user exists")
	}
}

// ─── CreateAdmin service tests ────────────────────────────────────────────────

func TestService_CreateAdmin(t *testing.T) {
	t.Parallel()
	// CreateAdmin should work even when allow_registration is false.
	svc := newUserService(t, false)
	ctx := context.Background()

	u, err := svc.CreateAdmin(ctx, "admin", "admin@example.com", "securepass")
	if err != nil {
		t.Fatalf("CreateAdmin: unexpected error: %v", err)
	}
	if !u.IsAdmin {
		t.Error("CreateAdmin: expected IsAdmin=true")
	}
	if !u.IsActive {
		t.Error("CreateAdmin: expected IsActive=true")
	}
	if u.ID == "" {
		t.Error("CreateAdmin: expected non-empty ID")
	}
}

func TestService_CreateAdmin_PasswordTooShort(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, false)

	_, err := svc.CreateAdmin(context.Background(), "admin", "admin@example.com", "short")
	if err == nil {
		t.Fatal("CreateAdmin: expected error for short password")
	}
	if !isErr(err, user.ErrPasswordTooShort) {
		t.Errorf("CreateAdmin: expected ErrPasswordTooShort, got %v", err)
	}
}

func TestService_CreateAdmin_UsernameRequired(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, false)

	_, err := svc.CreateAdmin(context.Background(), "", "admin@example.com", "securepass")
	if err == nil {
		t.Fatal("CreateAdmin: expected error for empty username")
	}
	if !isErr(err, user.ErrUsernameRequired) {
		t.Errorf("CreateAdmin: expected ErrUsernameRequired, got %v", err)
	}
}

// ─── Handler setup endpoint tests ────────────────────────────────────────────

func TestHandler_GetSetup_NoManager_Redirects(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, false)

	req := httptest.NewRequest(http.MethodGet, "/setup", nil)
	rec := httptest.NewRecorder()
	h.GetSetup(nil)(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("GetSetup with nil manager: expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("GetSetup with nil manager: expected redirect to /login, got %q", loc)
	}
}

func TestHandler_GetSetup_Active_Renders(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, false)

	mgr, _, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/setup", nil)
	rec := httptest.NewRecorder()
	h.GetSetup(mgr)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GetSetup with active manager: expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Initial Setup") {
		t.Error("GetSetup: expected 'Initial Setup' in response body")
	}
	if !strings.Contains(body, "setup_token") {
		t.Error("GetSetup: expected setup_token field in form")
	}
}

func TestHandler_PostSetup_ValidToken_CreatesAdmin(t *testing.T) {
	t.Parallel()
	f := newFullHandlerFixture(t, false)

	mgr, token, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: %v", err)
	}

	form := url.Values{
		"setup_token":      {token},
		"username":         {"admin"},
		"email":            {"admin@example.com"},
		"password":         {"securepass123"},
		"password_confirm": {"securepass123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	f.handler.PostSetup(mgr)(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("PostSetup: expected 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/admin" {
		t.Errorf("PostSetup: expected redirect to /admin, got %q", loc)
	}

	// Verify the admin user was actually created.
	has, err := user.NewStore(f.db).HasAdmin(context.Background())
	if err != nil {
		t.Fatalf("HasAdmin: %v", err)
	}
	if !has {
		t.Error("PostSetup: expected admin user to exist after setup")
	}

	// Token should be consumed — IsActive should now be false.
	if mgr.IsActive() {
		t.Error("PostSetup: expected token to be consumed after successful setup")
	}
}

func TestHandler_PostSetup_WrongToken(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, false)

	mgr, _, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: %v", err)
	}

	form := url.Values{
		"setup_token":      {"wrong-token"},
		"username":         {"admin"},
		"email":            {"admin@example.com"},
		"password":         {"securepass123"},
		"password_confirm": {"securepass123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.PostSetup(mgr)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("PostSetup with wrong token: expected 200 (form re-render), got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Invalid or expired setup token") {
		t.Errorf("PostSetup with wrong token: expected error message in body, got: %s", body)
	}
}

func TestHandler_PostSetup_PasswordMismatch(t *testing.T) {
	t.Parallel()
	h, _ := newHandlerFixture(t, false)

	mgr, token, err := user.NewSetupTokenManager()
	if err != nil {
		t.Fatalf("NewSetupTokenManager: %v", err)
	}

	form := url.Values{
		"setup_token":      {token},
		"username":         {"admin"},
		"email":            {"admin@example.com"},
		"password":         {"securepass123"},
		"password_confirm": {"different123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.PostSetup(mgr)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("PostSetup password mismatch: expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Passwords do not match") {
		t.Errorf("PostSetup password mismatch: expected error in body, got: %s", body)
	}
	// Token should NOT have been consumed on password mismatch — it's checked before Consume.
	if !mgr.IsActive() {
		t.Error("PostSetup password mismatch: token should still be active (checked before consume)")
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// isErr is a helper to check errors.Is (used in table-less subtests).
func isErr(err, target error) bool {
	return err != nil && strings.Contains(err.Error(), target.Error())
}
