package oauth_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/policy"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// multiAppClient resolves multiple OAuth apps by clientID for cross-client tests.
type multiAppClient struct {
	byClientID map[string]*app.App
	access     bool
}

func (m *multiAppClient) GetByClientID(_ context.Context, clientID string) (*app.App, error) {
	a, ok := m.byClientID[clientID]
	if !ok {
		return nil, app.ErrNotFound
	}
	return a, nil
}

func (m *multiAppClient) HasAccess(_ context.Context, _, _ string) (bool, error) {
	return m.access, nil
}

func (m *multiAppClient) TokenAssignments(_ context.Context, _, _ string) ([]string, []string, error) {
	return []string{}, []string{}, nil
}

func (m *multiAppClient) EvaluateAccess(_ context.Context, a *app.App, _ string, isAdmin bool, clientIP string, now time.Time) (policy.Decision, error) {
	return policy.Evaluate(policy.Input{
		Policy:   a.Policy(),
		IsAdmin:  isAdmin,
		ClientIP: clientIP,
		Now:      now,
	})
}

// seedAdditionalApp inserts another OAuth-enabled app row into db and sets a.ID.
func seedAdditionalApp(t *testing.T, db *sql.DB, a *app.App) {
	t.Helper()
	now := time.Now().UTC()
	appID := fmt.Sprintf("app-extra-%s-%d", a.ClientID, now.UnixNano())
	_, err := db.Exec(`
		INSERT INTO apps (id, slug, name, description, host_pattern, is_active,
		                  client_id, client_secret_hash, redirect_uris, oauth_enabled,
		                  created_at, updated_at)
		VALUES (?, ?, ?, '', '', 1, ?, ?, ?, 1, ?, ?)`,
		appID,
		"slug-"+appID,
		"App "+a.ClientID,
		a.ClientID,
		a.ClientSecretHash,
		joinURIs(a.RedirectURIs),
		now, now,
	)
	if err != nil {
		t.Fatalf("seedAdditionalApp(%s): %v", a.ClientID, err)
	}
	a.ID = appID
}

// TestRegression_DeleteExpired_PreservesUsedRefreshTokenTombstones verifies
// that periodic cleanup via DeleteExpired retains used refresh-token rows until
// expires_at passes so OAuth 2.1 §6.1 replay detection still revokes the family
// after cleanup runs.
func TestRegression_DeleteExpired_PreservesUsedRefreshTokenTombstones(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)

	const (
		clientID    = "replay-cleanup-client"
		plainSecret = "replay-cleanup-secret"
		redirectURI = "https://app.example.com/callback"
	)

	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
	tc := newTestServiceWithDB(t, db, testApp, testUser)

	// Step 1: issue initial authorization code and exchange for refresh token rt1.
	code, err := tc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", "st", "", "", "", time.Now().UTC(), tc.userID, "")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	resp1, err := tc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	rt1 := resp1.RefreshToken

	// Step 2: rotate rt1 -> rt2. rt1 is now marked used (used_at != NULL) while
	// its expires_at is still in the future.
	resp2, err := tc.svc.RefreshTokens(ctx, rt1, clientID, plainSecret, "", "", "")
	if err != nil {
		t.Fatalf("RefreshTokens(rt1): %v", err)
	}
	rt2 := resp2.RefreshToken

	// Step 3: run periodic cleanup. Used refresh-token tombstone must survive
	// until its expires_at passes.
	if err := tc.store.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	tombstone, err := tc.store.GetRefreshToken(ctx, rt1)
	if err != nil {
		t.Fatalf("GetRefreshToken(rt1) after DeleteExpired: got %v, want preserved tombstone", err)
	}
	if tombstone.UsedAt == nil {
		t.Fatal("GetRefreshToken(rt1): expected UsedAt to be non-nil")
	}

	// Step 4: replaying rt1 after DeleteExpired must still trigger reuse
	// detection and revoke the entire rotation family (including active rt2).
	_, err = tc.svc.RefreshTokens(ctx, rt1, clientID, plainSecret, "", "", "")
	if !errors.Is(err, oauth.ErrRefreshTokenReuse) {
		t.Fatalf("RefreshTokens(replayed rt1): got %v, want ErrRefreshTokenReuse", err)
	}
	var reuseErr *oauth.RefreshTokenReuseError
	if !errors.As(err, &reuseErr) {
		t.Fatalf("RefreshTokens(replayed rt1): expected *RefreshTokenReuseError, got %T", err)
	}

	if _, err := tc.svc.RefreshTokens(ctx, rt2, clientID, plainSecret, "", "", ""); !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("RefreshTokens(rt2 after family revocation): got %v, want ErrRefreshNotFound", err)
	}
	if _, err := tc.store.GetRefreshToken(ctx, rt2); !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("GetRefreshToken(rt2 after family revocation): got %v, want ErrRefreshNotFound", err)
	}

	// Step 5: once a used refresh token's expires_at IS in the past,
	// DeleteExpired must prune it so tombstones do not accumulate forever.
	expiredUsed := &oauth.RefreshToken{
		AppID:     tc.appID,
		UserID:    tc.userID,
		Scopes:    "openid",
		ExpiresAt: time.Now().UTC().Add(-time.Minute),
	}
	if err := tc.store.CreateRefreshToken(ctx, expiredUsed); err != nil {
		t.Fatalf("CreateRefreshToken(expiredUsed): %v", err)
	}
	if err := tc.store.MarkRefreshTokenUsed(ctx, expiredUsed.Token); err != nil {
		t.Fatalf("MarkRefreshTokenUsed(expiredUsed): %v", err)
	}
	if err := tc.store.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired(expiredUsed): %v", err)
	}
	if _, err := tc.store.GetRefreshToken(ctx, expiredUsed.Token); !errors.Is(err, oauth.ErrRefreshNotFound) {
		t.Fatalf("GetRefreshToken(expiredUsed) after DeleteExpired: got %v, want ErrRefreshNotFound", err)
	}
}

// TestRegression_DeleteExpired_PreservesActiveRevokedJTIAcrossTimezones
// verifies that DeleteExpired does not prematurely delete active revoked JWT
// JTIs when RevokeJTI receives timestamps in UTC or non-UTC timezone offsets
// (e.g., UTC-5), while still pruning genuinely expired entries.
func TestRegression_DeleteExpired_PreservesActiveRevokedJTIAcrossTimezones(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	utcMinus5 := time.FixedZone("UTC-5", -5*3600)
	utcPlus5 := time.FixedZone("UTC+5", 5*3600)
	now := time.Now()

	tests := []struct {
		name        string
		jti         string
		expiresAt   time.Time
		wantRevoked bool
	}{
		{
			name:        "active_utc",
			jti:         "jti-active-utc",
			expiresAt:   now.UTC().Add(30 * time.Minute),
			wantRevoked: true,
		},
		{
			name:        "active_utc_minus_5",
			jti:         "jti-active-utc-minus-5",
			expiresAt:   now.In(utcMinus5).Add(30 * time.Minute),
			wantRevoked: true,
		},
		{
			name:        "active_utc_plus_5",
			jti:         "jti-active-utc-plus-5",
			expiresAt:   now.In(utcPlus5).Add(30 * time.Minute),
			wantRevoked: true,
		},
		{
			name:        "expired_utc",
			jti:         "jti-expired-utc",
			expiresAt:   now.UTC().Add(-30 * time.Minute),
			wantRevoked: false,
		},
		{
			name:        "expired_utc_minus_5",
			jti:         "jti-expired-utc-minus-5",
			expiresAt:   now.In(utcMinus5).Add(-30 * time.Minute),
			wantRevoked: false,
		},
		{
			name:        "expired_utc_plus_5",
			jti:         "jti-expired-utc-plus-5",
			expiresAt:   now.In(utcPlus5).Add(-30 * time.Minute),
			wantRevoked: false,
		},
	}

	for _, tc := range tests {
		if err := store.RevokeJTI(ctx, tc.jti, tc.expiresAt); err != nil {
			t.Fatalf("RevokeJTI(%s): %v", tc.name, err)
		}
	}

	if err := store.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			revoked, err := store.IsJTIRevoked(ctx, tc.jti)
			if err != nil {
				t.Fatalf("IsJTIRevoked(%s): %v", tc.jti, err)
			}
			if revoked != tc.wantRevoked {
				t.Errorf("IsJTIRevoked(%s) = %v, want %v (expiresAt=%s)", tc.jti, revoked, tc.wantRevoked, tc.expiresAt.Format(time.RFC3339))
			}
		})
	}

	t.Run("revoked_jwt_remains_rejected_after_delete_expired", func(t *testing.T) {
		const (
			clientID    = "jti-cleanup-client"
			plainSecret = "jti-cleanup-secret"
			redirectURI = "https://app.example.com/callback"
		)
		svcDB := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "bob", Email: "bob@example.com", Name: "Bob"}
		tc := newTestServiceWithDB(t, svcDB, testApp, testUser)

		code, err := tc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", "", "", "", "", time.Now().UTC(), tc.userID, "")
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		tokResp, err := tc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI, "", "", "")
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}
		if err := tc.svc.RevokeToken(ctx, tokResp.AccessToken, "access_token", clientID, plainSecret); err != nil {
			t.Fatalf("RevokeToken: %v", err)
		}
		if err := tc.store.DeleteExpired(ctx); err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if _, _, err := tc.svc.ValidateAccessToken(ctx, tokResp.AccessToken); !errors.Is(err, oauth.ErrTokenRevoked) {
			t.Fatalf("ValidateAccessToken after DeleteExpired: got %v, want ErrTokenRevoked", err)
		}
	})
}

// TestRegression_TokenEndpoint_ClientIDMismatchReturnsInvalidGrant verifies
// that presenting another client's authorization code or refresh token at
// POST /oauth/token returns 400 Bad Request with error="invalid_grant", never
// 500 Internal Server Error.
func TestRegression_TokenEndpoint_ClientIDMismatchReturnsInvalidGrant(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := oauth.NewStore(db)

	const (
		clientAID    = "client-a"
		secretA      = "secret-a"
		redirectURIA = "https://app-a.example.com/callback"

		clientBID    = "client-b"
		secretB      = "secret-b"
		redirectURIB = "https://app-b.example.com/callback"
	)

	appA := buildTestApp(t, clientAID, secretA, []string{redirectURIA})
	appB := buildTestApp(t, clientBID, secretB, []string{redirectURIB})
	testUser := &user.User{Username: "carol", Email: "carol@example.com", Name: "Carol"}

	appAID, userID := seedAppAndUserWithCredentials(t, db, appA, testUser)
	appA.ID = appAID
	testUser.ID = userID
	testUser.IsActive = true
	seedAdditionalApp(t, db, appB)

	apps := &multiAppClient{
		byClientID: map[string]*app.App{
			clientAID: appA,
			clientBID: appB,
		},
		access: true,
	}
	users := &fakeUserReader{u: testUser}

	svc, err := oauth.NewService(ctx, store, apps, users, "https://auth.example.com", slog.Default())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	h := oauth.NewHandler(svc, &fakeSessionValidator{}, "https://auth.example.com", nil, testConfig(), slog.Default())
	router := newTestRouter(h)

	// Issue a code belonging to client-a (kept unused for the code-mismatch tests).
	codeForA, err := svc.Authorize(ctx, clientAID, redirectURIA, "openid", "", "", "", "", "", time.Now().UTC(), userID, "")
	if err != nil {
		t.Fatalf("Authorize(codeForA): %v", err)
	}

	// Issue and exchange a second code for client-a to obtain a refresh token belonging to client-a.
	codeForRefresh, err := svc.Authorize(ctx, clientAID, redirectURIA, "openid", "", "", "", "", "", time.Now().UTC(), userID, "")
	if err != nil {
		t.Fatalf("Authorize(codeForRefresh): %v", err)
	}
	tokRespA, err := svc.ExchangeCode(ctx, codeForRefresh.Code, clientAID, secretA, redirectURIA, "", "", "")
	if err != nil {
		t.Fatalf("ExchangeCode(client-a): %v", err)
	}

	tests := []struct {
		name     string
		useBasic bool
		form     url.Values
	}{
		{
			name:     "authorization_code_form_credentials",
			useBasic: false,
			form: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {codeForA.Code},
				"redirect_uri":  {redirectURIA},
				"client_id":     {clientBID},
				"client_secret": {secretB},
			},
		},
		{
			name:     "authorization_code_basic_auth",
			useBasic: true,
			form: url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {codeForA.Code},
				"redirect_uri": {redirectURIA},
			},
		},
		{
			name:     "refresh_token_form_credentials",
			useBasic: false,
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {tokRespA.RefreshToken},
				"client_id":     {clientBID},
				"client_secret": {secretB},
			},
		},
		{
			name:     "refresh_token_basic_auth",
			useBasic: true,
			form: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {tokRespA.RefreshToken},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.useBasic {
				req.SetBasicAuth(clientBID, secretB)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("POST /oauth/token: status %d, want 400 Bad Request (body=%s)", w.Code, w.Body.String())
			}

			var errBody map[string]string
			if err := json.NewDecoder(w.Body).Decode(&errBody); err != nil {
				t.Fatalf("decode JSON error body: %v", err)
			}
			if errBody["error"] != "invalid_grant" {
				t.Errorf("error = %q, want %q (body=%v)", errBody["error"], "invalid_grant", errBody)
			}
		})
	}

	// Verify client-a's grants were not burned or revoked by client-b's mismatched attempts.
	if _, err := svc.ExchangeCode(ctx, codeForA.Code, clientAID, secretA, redirectURIA, "", "", ""); err != nil {
		t.Errorf("ExchangeCode(client-a) after mismatched attempt: %v", err)
	}
	if _, err := svc.RefreshTokens(ctx, tokRespA.RefreshToken, clientAID, secretA, "", "", ""); err != nil {
		t.Errorf("RefreshTokens(client-a) after mismatched attempt: %v", err)
	}
}
