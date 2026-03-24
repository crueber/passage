package oauth_test

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

// fakeAppClient implements oauth's appClient interface for testing.
type fakeAppClient struct {
	app    *app.App
	getErr error
	access bool
	accErr error
}

func (f *fakeAppClient) GetByClientID(_ context.Context, _ string) (*app.App, error) {
	return f.app, f.getErr
}

func (f *fakeAppClient) HasAccess(_ context.Context, _, _ string) (bool, error) {
	return f.access, f.accErr
}

// fakeUserReader implements oauth's userReader interface for testing.
type fakeUserReader struct {
	u      *user.User
	getErr error
}

func (f *fakeUserReader) GetByID(_ context.Context, _ string) (*user.User, error) {
	return f.u, f.getErr
}

// testServiceContext holds everything created by newTestServiceWithDB.
type testServiceContext struct {
	svc    *oauth.Service
	store  *oauth.SQLiteStore
	appID  string
	userID string
}

// newTestServiceWithDB creates a Service backed by a real SQLiteStore, seeds
// a real app and user row, and returns the service plus the seeded IDs.
// The fakeAppClient's app.ID is updated to match the seeded app ID.
// The fakeUserReader's user.ID is updated to match the seeded user ID.
func newTestServiceWithDB(t *testing.T, db *sql.DB, testApp *app.App, testUser *user.User) *testServiceContext {
	t.Helper()

	store := oauth.NewStore(db)

	pemBytes, kid, err := store.GetOrCreateRSAKey(context.Background())
	if err != nil {
		t.Fatalf("newTestServiceWithDB: GetOrCreateRSAKey: %v", err)
	}

	// Seed the DB with real rows that the FK constraints require.
	appID, userID := seedAppAndUserWithCredentials(t, db, testApp, testUser)

	// Update the fake structs so they reflect the real DB IDs.
	testApp.ID = appID
	testUser.ID = userID

	apps := &fakeAppClient{app: testApp, access: true}
	users := &fakeUserReader{u: testUser}

	svc, err := oauth.NewService(store, apps, users, pemBytes, kid, "https://auth.example.com", slog.Default())
	if err != nil {
		t.Fatalf("newTestServiceWithDB: NewService: %v", err)
	}

	return &testServiceContext{
		svc:    svc,
		store:  store,
		appID:  appID,
		userID: userID,
	}
}

// seedAppAndUserWithCredentials seeds an app and user row using data from the
// test fixtures, so FK constraints are satisfied and the fake clients have
// consistent IDs.
func seedAppAndUserWithCredentials(t *testing.T, db *sql.DB, a *app.App, u *user.User) (appID, userID string) {
	t.Helper()

	appID, userID = seedAppAndUser(t, db)

	// Update the client_id and client_secret_hash for the seeded app.
	now := time.Now().UTC()
	_, err := db.Exec(`
		UPDATE apps SET client_id = ?, client_secret_hash = ?, redirect_uris = ?, oauth_enabled = 1, updated_at = ?
		WHERE id = ?`,
		a.ClientID,
		a.ClientSecretHash,
		joinURIs(a.RedirectURIs),
		now,
		appID,
	)
	if err != nil {
		t.Fatalf("seedAppAndUserWithCredentials: update app: %v", err)
	}

	return appID, userID
}

// joinURIs joins redirect URIs with a newline separator, matching app store convention.
func joinURIs(uris []string) string {
	result := ""
	for i, u := range uris {
		if i > 0 {
			result += "\n"
		}
		result += u
	}
	return result
}

// buildTestApp creates an app.App with a bcrypt-hashed client secret.
// The ID field is a placeholder that will be replaced by newTestServiceWithDB.
func buildTestApp(t *testing.T, clientID, plainSecret string, redirectURIs []string) *app.App {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), 10)
	if err != nil {
		t.Fatalf("buildTestApp: bcrypt: %v", err)
	}
	return &app.App{
		ID:               "placeholder-replaced-by-seed",
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		RedirectURIs:     redirectURIs,
		OAuthEnabled:     true,
	}
}

func TestService_Authorize(t *testing.T) {

	const (
		clientID    = "test-client"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	tests := []struct {
		name        string
		setupApp    func(t *testing.T) *app.App
		setupAccess bool
		clientID    string
		redirectURI string
		wantErr     error
		wantNoErr   bool // use for "expect some error, but not a specific sentinel"
	}{
		{
			name:        "success",
			setupApp:    func(t *testing.T) *app.App { return buildTestApp(t, clientID, plainSecret, []string{redirectURI}) },
			setupAccess: true,
			clientID:    clientID,
			redirectURI: redirectURI,
		},
		{
			name:        "redirect_uri_mismatch",
			setupApp:    func(t *testing.T) *app.App { return buildTestApp(t, clientID, plainSecret, []string{redirectURI}) },
			setupAccess: true,
			clientID:    clientID,
			redirectURI: "https://evil.example.com/callback",
			wantErr:     app.ErrRedirectURIMismatch,
		},
		{
			name:        "no_access",
			setupApp:    func(t *testing.T) *app.App { return buildTestApp(t, clientID, plainSecret, []string{redirectURI}) },
			setupAccess: false,
			clientID:    clientID,
			redirectURI: redirectURI,
			wantNoErr:   true, // expect some error
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := testutil.NewTestDB(t)
			testApp := tc.setupApp(t)
			testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
			sc := newTestServiceWithDB(t, db, testApp, testUser)

			// Override access if needed.
			// We re-wire the apps fake; the service uses it directly.
			// For "no_access", we need to rebuild service with access=false.
			// Simpler: pass access flag separately.
			if !tc.setupAccess {
				// Rebuild with access=false
				store := oauth.NewStore(db)
				pemBytes, kid, err := store.GetOrCreateRSAKey(context.Background())
				if err != nil {
					t.Fatalf("GetOrCreateRSAKey: %v", err)
				}
				apps := &fakeAppClient{app: testApp, access: false}
				users := &fakeUserReader{u: testUser}
				svc, err := oauth.NewService(store, apps, users, pemBytes, kid, "https://auth.example.com", slog.Default())
				if err != nil {
					t.Fatalf("NewService: %v", err)
				}
				sc.svc = svc
			}

			code, err := sc.svc.Authorize(context.Background(), tc.clientID, tc.redirectURI, "openid", "state-1", testUser.ID)

			if tc.wantNoErr {
				if err == nil {
					t.Error("expected an error, got nil")
				}
				return
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("Authorize error: got %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Authorize unexpected error: %v", err)
			}
			if code == nil || code.Code == "" {
				t.Error("Authorize: expected non-empty code")
			}
		})
	}

	// Test cases that need a custom fakeAppClient (don't hit DB).
	t.Run("invalid_client_not_found", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		// Override apps to return not-found.
		store := oauth.NewStore(db)
		pemBytes, kid, err := store.GetOrCreateRSAKey(context.Background())
		if err != nil {
			t.Fatalf("GetOrCreateRSAKey: %v", err)
		}
		apps := &fakeAppClient{getErr: app.ErrNotFound}
		users := &fakeUserReader{u: testUser}
		svc, err := oauth.NewService(store, apps, users, pemBytes, kid, "https://auth.example.com", slog.Default())
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		sc.svc = svc

		_, gotErr := sc.svc.Authorize(context.Background(), "unknown-client", redirectURI, "openid", "", testUser.ID)
		if !errors.Is(gotErr, app.ErrOAuthNotEnabled) {
			t.Errorf("invalid client: got %v, want ErrOAuthNotEnabled", gotErr)
		}
	})

	t.Run("oauth_not_enabled", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		disabledApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		disabledApp.OAuthEnabled = false

		sc := newTestServiceWithDB(t, db, disabledApp, testUser)

		store := oauth.NewStore(db)
		pemBytes, kid, err := store.GetOrCreateRSAKey(context.Background())
		if err != nil {
			t.Fatalf("GetOrCreateRSAKey: %v", err)
		}
		apps := &fakeAppClient{app: disabledApp, access: true}
		users := &fakeUserReader{u: testUser}
		svc, err := oauth.NewService(store, apps, users, pemBytes, kid, "https://auth.example.com", slog.Default())
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		sc.svc = svc

		_, gotErr := sc.svc.Authorize(context.Background(), clientID, redirectURI, "openid", "", testUser.ID)
		if !errors.Is(gotErr, app.ErrOAuthNotEnabled) {
			t.Errorf("oauth not enabled: got %v, want ErrOAuthNotEnabled", gotErr)
		}
	})
}

func TestService_ExchangeCode(t *testing.T) {
	ctx := context.Background()

	const (
		clientID    = "test-client"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	t.Run("success", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}

		resp, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}
		if resp.AccessToken == "" {
			t.Error("ExchangeCode: empty access_token")
		}
		if resp.RefreshToken == "" {
			t.Error("ExchangeCode: empty refresh_token")
		}
		if resp.IDToken == "" {
			t.Error("ExchangeCode: empty id_token")
		}
		if resp.TokenType != "Bearer" {
			t.Errorf("ExchangeCode token_type: got %q, want %q", resp.TokenType, "Bearer")
		}
	})

	t.Run("expired_code", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		expiredCode := &oauth.Code{
			AppID:       sc.appID,
			UserID:      sc.userID,
			RedirectURI: redirectURI,
			Scopes:      "openid",
			ExpiresAt:   time.Now().UTC().Add(-1 * time.Hour),
		}
		if err := sc.store.CreateCode(ctx, expiredCode); err != nil {
			t.Fatalf("CreateCode: %v", err)
		}

		_, err := sc.svc.ExchangeCode(ctx, expiredCode.Code, clientID, plainSecret, redirectURI)
		if !errors.Is(err, oauth.ErrCodeExpired) {
			t.Errorf("ExchangeCode expired: got %v, want ErrCodeExpired", err)
		}
	})

	t.Run("used_code", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}

		// Exchange once.
		if _, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI); err != nil {
			t.Fatalf("ExchangeCode first use: %v", err)
		}

		// Exchange again — should fail with ErrCodeUsed.
		_, err = sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
		if !errors.Is(err, oauth.ErrCodeUsed) {
			t.Errorf("ExchangeCode used: got %v, want ErrCodeUsed", err)
		}
	})

	t.Run("wrong_client", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}

		// Exchange with a different app ID.
		wrongApp := buildTestApp(t, "wrong-client", plainSecret, []string{redirectURI})
		wrongApp.ID = "different-app-id" // this ID won't match the code's app_id
		store := oauth.NewStore(db)
		pemBytes, kid, _ := store.GetOrCreateRSAKey(ctx)
		svc2, _ := oauth.NewService(store,
			&fakeAppClient{app: wrongApp, access: true},
			&fakeUserReader{u: testUser},
			pemBytes, kid, "https://auth.example.com", slog.Default(),
		)

		_, err = svc2.ExchangeCode(ctx, code.Code, "wrong-client", plainSecret, redirectURI)
		if err == nil {
			t.Error("ExchangeCode wrong client: expected error, got nil")
		}
	})

	t.Run("wrong_secret", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}

		_, err = sc.svc.ExchangeCode(ctx, code.Code, clientID, "wrong-secret", redirectURI)
		if !errors.Is(err, app.ErrInvalidClientSecret) {
			t.Errorf("ExchangeCode wrong secret: got %v, want ErrInvalidClientSecret", err)
		}
	})

	t.Run("redirect_mismatch", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}

		_, err = sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, "https://different.example.com/cb")
		if !errors.Is(err, app.ErrRedirectURIMismatch) {
			t.Errorf("ExchangeCode redirect mismatch: got %v, want ErrRedirectURIMismatch", err)
		}
	})
}

func TestService_RefreshTokens(t *testing.T) {
	ctx := context.Background()

	const (
		clientID    = "test-client"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	t.Run("success_and_rotation", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		// Get a refresh token via full code exchange.
		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		tokenResp, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}

		// Refresh.
		refreshResp, err := sc.svc.RefreshTokens(ctx, tokenResp.RefreshToken, clientID, plainSecret)
		if err != nil {
			t.Fatalf("RefreshTokens: %v", err)
		}
		if refreshResp.AccessToken == "" {
			t.Error("RefreshTokens: empty access_token")
		}
		if refreshResp.RefreshToken == "" {
			t.Error("RefreshTokens: empty refresh_token")
		}
		if refreshResp.IDToken == "" {
			t.Error("RefreshTokens: empty id_token")
		}
		// New refresh token must differ from the old one (rotation).
		if refreshResp.RefreshToken == tokenResp.RefreshToken {
			t.Error("RefreshTokens: expected rotated refresh token but got same value")
		}

		// Second use of the old refresh token must fail.
		_, err = sc.svc.RefreshTokens(ctx, tokenResp.RefreshToken, clientID, plainSecret)
		if !errors.Is(err, oauth.ErrRefreshUsed) {
			t.Errorf("RefreshTokens second use: got %v, want ErrRefreshUsed", err)
		}
	})

	t.Run("expired_refresh", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		expiredRT := &oauth.RefreshToken{
			AppID:     sc.appID,
			UserID:    sc.userID,
			Scopes:    "openid",
			ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		}
		if err := sc.store.CreateRefreshToken(ctx, expiredRT); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}

		_, err := sc.svc.RefreshTokens(ctx, expiredRT.Token, clientID, plainSecret)
		if !errors.Is(err, oauth.ErrRefreshExpired) {
			t.Errorf("RefreshTokens expired: got %v, want ErrRefreshExpired", err)
		}
	})

	t.Run("wrong_client", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		tokenResp, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}

		wrongApp := buildTestApp(t, "other-client", plainSecret, []string{redirectURI})
		wrongApp.ID = "different-app-id"
		store := oauth.NewStore(db)
		pemBytes, kid, _ := store.GetOrCreateRSAKey(ctx)
		svc2, _ := oauth.NewService(store,
			&fakeAppClient{app: wrongApp, access: true},
			&fakeUserReader{u: testUser},
			pemBytes, kid, "https://auth.example.com", slog.Default(),
		)

		_, err = svc2.RefreshTokens(ctx, tokenResp.RefreshToken, "other-client", plainSecret)
		if err == nil {
			t.Error("RefreshTokens wrong client: expected error, got nil")
		}
	})

	t.Run("wrong_secret", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		tokenResp, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}

		_, err = sc.svc.RefreshTokens(ctx, tokenResp.RefreshToken, clientID, "bad-secret")
		if !errors.Is(err, app.ErrInvalidClientSecret) {
			t.Errorf("RefreshTokens wrong secret: got %v, want ErrInvalidClientSecret", err)
		}
	})
}

func TestService_ValidateAccessToken(t *testing.T) {
	ctx := context.Background()

	const (
		clientID    = "test-client"
		plainSecret = "test-secret"
		redirectURI = "https://example.com/callback"
	)

	t.Run("valid_token_returns_user", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid", "", testUser.ID)
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		tokenResp, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
		if err != nil {
			t.Fatalf("ExchangeCode: %v", err)
		}

		u, tok, err := sc.svc.ValidateAccessToken(ctx, tokenResp.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken: %v", err)
		}
		if u.ID != testUser.ID {
			t.Errorf("ValidateAccessToken user ID: got %q, want %q", u.ID, testUser.ID)
		}
		if tok.Token != tokenResp.AccessToken {
			t.Errorf("ValidateAccessToken token: got %q, want %q", tok.Token, tokenResp.AccessToken)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		_, _, err := sc.svc.ValidateAccessToken(ctx, "nonexistent-token-xyz")
		if !errors.Is(err, oauth.ErrTokenNotFound) {
			t.Errorf("ValidateAccessToken not found: got %v, want ErrTokenNotFound", err)
		}
	})

	t.Run("expired_returns_ErrTokenExpired", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
		testUser := &user.User{Username: "alice", Email: "alice@example.com", Name: "Alice"}
		sc := newTestServiceWithDB(t, db, testApp, testUser)

		expiredToken := &oauth.Token{
			AppID:     sc.appID,
			UserID:    sc.userID,
			Scopes:    "openid",
			ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		}
		if err := sc.store.CreateToken(ctx, expiredToken); err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		_, _, err := sc.svc.ValidateAccessToken(ctx, expiredToken.Token)
		if !errors.Is(err, oauth.ErrTokenExpired) {
			t.Errorf("ValidateAccessToken expired: got %v, want ErrTokenExpired", err)
		}
	})
}

// TestService_ExchangeCode_IDTokenClaims verifies that the id_token JWT
// produced by ExchangeCode contains the correct claims and a valid RS256 signature.
func TestService_ExchangeCode_IDTokenClaims(t *testing.T) {
	const (
		clientID    = "test-client-claims"
		plainSecret = "test-secret-claims"
		redirectURI = "https://example.com/callback"
		baseURL     = "https://auth.example.com"
	)

	db := testutil.NewTestDB(t)
	testApp := buildTestApp(t, clientID, plainSecret, []string{redirectURI})
	testUser := &user.User{
		Username: "claimsuser",
		Email:    "claims@example.com",
		Name:     "Claims User",
		IsAdmin:  false,
	}
	sc := newTestServiceWithDB(t, db, testApp, testUser)

	ctx := context.Background()

	// Step 1: Get an authorization code.
	code, err := sc.svc.Authorize(ctx, clientID, redirectURI, "openid profile email", "", testUser.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	// Step 2: Exchange it for a TokenResponse containing an id_token.
	tokenResp, err := sc.svc.ExchangeCode(ctx, code.Code, clientID, plainSecret, redirectURI)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}

	// Step 3: Decode the id_token JWT payload (without verifying signature yet).
	parts := strings.Split(tokenResp.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token: expected 3 parts, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("id_token: base64 decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("id_token: unmarshal payload: %v", err)
	}

	// Step 4: Assert standard OIDC claims.
	now := time.Now().Unix()

	if sub, _ := claims["sub"].(string); sub != testUser.ID {
		t.Errorf("id_token sub: got %q, want %q", sub, testUser.ID)
	}
	if iss, _ := claims["iss"].(string); iss != baseURL {
		t.Errorf("id_token iss: got %q, want %q", iss, baseURL)
	}

	// aud may be a string or []any depending on the JWT library serialisation.
	switch aud := claims["aud"].(type) {
	case string:
		if aud != clientID {
			t.Errorf("id_token aud (string): got %q, want %q", aud, clientID)
		}
	case []any:
		found := false
		for _, v := range aud {
			if v == clientID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("id_token aud (array): %v does not contain %q", aud, clientID)
		}
	default:
		t.Errorf("id_token aud: unexpected type %T: %v", claims["aud"], claims["aud"])
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Errorf("id_token exp: not a number: %T", claims["exp"])
	} else if int64(exp) <= now {
		t.Errorf("id_token exp: %d is not in the future (now=%d)", int64(exp), now)
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Errorf("id_token iat: not a number: %T", claims["iat"])
	} else if int64(iat) > now {
		t.Errorf("id_token iat: %d is in the future (now=%d)", int64(iat), now)
	}

	if email, _ := claims["email"].(string); email != testUser.Email {
		t.Errorf("id_token email: got %q, want %q", email, testUser.Email)
	}
	if username, _ := claims["preferred_username"].(string); username != testUser.Username {
		t.Errorf("id_token preferred_username: got %q, want %q", username, testUser.Username)
	}
	isAdmin, ok := claims["is_admin"].(bool)
	if !ok {
		t.Errorf("id_token is_admin: expected bool, got %T", claims["is_admin"])
	} else if isAdmin != testUser.IsAdmin {
		t.Errorf("id_token is_admin: got %v, want %v", isAdmin, testUser.IsAdmin)
	}

	// Step 5: Verify the RS256 signature using the service's public key.
	pubKey := sc.svc.PrivateKey().Public().(*rsa.PublicKey)
	parsed, err := jwtlib.Parse(tokenResp.IDToken, func(token *jwtlib.Token) (any, error) {
		if _, ok := token.Method.(*jwtlib.SigningMethodRSA); !ok {
			return nil, jwtlib.ErrSignatureInvalid
		}
		return pubKey, nil
	})
	if err != nil {
		t.Errorf("id_token RS256 signature verification failed: %v", err)
	}
	if parsed != nil && !parsed.Valid {
		t.Error("id_token: parsed token is not valid")
	}
}
