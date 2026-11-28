package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/policy"
	"github.com/crueber/passage/internal/user"
)

// appClient is the minimal interface needed from the app package.
// Defined here at the consumer boundary, per Go convention.
type appClient interface {
	GetByClientID(ctx context.Context, clientID string) (*app.App, error)
	HasAccess(ctx context.Context, userID, appID string) (bool, error)
	// TokenAssignments resolves a user's app-scoped role names and effective
	// (direct plus role-inherited) group names for token claims.
	TokenAssignments(ctx context.Context, userID, appID string) (roles, groups []string, err error)
	// EvaluateAccess applies the app's access policy to the user at
	// authorization time. An error means the policy could not be evaluated and
	// must be treated as a denial.
	EvaluateAccess(ctx context.Context, a *app.App, userID string, isAdmin bool, clientIP string, now time.Time) (policy.Decision, error)
}

// userReader is the minimal interface needed from the user package.
// Defined here at the consumer boundary, per Go convention.
type userReader interface {
	GetByID(ctx context.Context, id string) (*user.User, error)
}

// Token TTL constants for the OAuth2/OIDC flows.
const (
	authCodeTTL     = 10 * time.Minute
	accessTokenTTL  = 1 * time.Hour
	refreshTokenTTL = 30 * 24 * time.Hour
	idTokenTTL      = 1 * time.Hour
)

// Service implements the OAuth2/OIDC business logic.
type Service struct {
	store   Store
	apps    appClient
	users   userReader
	baseURL string
	logger  *slog.Logger

	// keys holds an immutable keyring snapshot. keysMu serialises signing-key
	// mutations and reloads so concurrent admin actions cannot install a stale
	// snapshot over a newer one while reads remain lock-free via atomic load.
	keysMu sync.Mutex
	keys   atomic.Pointer[Keyring]
}

// NewService constructs a Service and loads the OIDC signing keyring.
//
// It ensures at least one signing key exists (importing the legacy single key
// on first start), so a Service is never constructed without a usable key.
func NewService(ctx context.Context, store Store, apps appClient, users userReader, baseURL string, logger *slog.Logger) (*Service, error) {
	s := &Service{
		store:   store,
		apps:    apps,
		users:   users,
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		logger:  logger,
	}
	if err := store.EnsureSigningKeys(ctx); err != nil {
		return nil, fmt.Errorf("oauth service: ensure signing keys: %w", err)
	}
	if err := s.ReloadSigningKeys(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// ReloadSigningKeys rebuilds the keyring from the store and installs it.
// Called at startup and after every rotation, retirement, or deletion.
func (s *Service) ReloadSigningKeys(ctx context.Context) error {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	return s.reloadSigningKeysLocked(ctx)
}

func (s *Service) reloadSigningKeysLocked(ctx context.Context) error {
	keys, err := s.store.ListSigningKeys(ctx)
	if err != nil {
		return fmt.Errorf("oauth service: list signing keys: %w", err)
	}
	ring, err := newKeyring(keys)
	if err != nil {
		return fmt.Errorf("oauth service: build keyring: %w", err)
	}
	s.keys.Store(ring)
	return nil
}

// keyring returns the current snapshot, or nil before the first load.
func (s *Service) keyring() *Keyring {
	return s.keys.Load()
}

// ActiveSigningKeys returns the non-retired keys, newest first. These are
// served by the JWKS endpoint and accepted for verification.
func (s *Service) ActiveSigningKeys() []*SigningKey {
	return s.keyring().Active()
}

// CurrentSigningKey returns the key that signs new id_tokens: the newest
// non-retired key.
func (s *Service) CurrentSigningKey() (*SigningKey, error) {
	key := s.keyring().Current()
	if key == nil {
		return nil, ErrNoSigningKey
	}
	return key, nil
}

// ListSigningKeys returns the full key history for the admin UI, newest first.
func (s *Service) ListSigningKeys(ctx context.Context) ([]*SigningKey, error) {
	keys, err := s.store.ListSigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauth service: list signing keys: %w", err)
	}
	return keys, nil
}

// RotateSigningKey generates a new 2048-bit RSA key and makes it current. The
// previous key is left active so every id_token it signed keeps verifying
// until it expires; retiring it is a separate, explicit action.
func (s *Service) RotateSigningKey(ctx context.Context) (*SigningKey, error) {
	key, err := generateSigningKey()
	if err != nil {
		return nil, err
	}
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	if err := s.store.CreateSigningKey(ctx, key); err != nil {
		return nil, fmt.Errorf("oauth service: rotate signing key: %w", err)
	}
	if err := s.reloadSigningKeysLocked(ctx); err != nil {
		return nil, err
	}
	s.logger.Info("oauth signing key rotated", "kid", key.KID)
	return key, nil
}

// RetireSigningKey stops a key being served and accepted. The last active key
// cannot be retired.
func (s *Service) RetireSigningKey(ctx context.Context, kid string) error {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	if err := s.store.RetireSigningKey(ctx, kid); err != nil {
		return fmt.Errorf("oauth service: retire signing key: %w", err)
	}
	if err := s.reloadSigningKeysLocked(ctx); err != nil {
		return err
	}
	s.logger.Info("oauth signing key retired", "kid", kid)
	return nil
}

// DeleteSigningKey removes a retired key permanently.
func (s *Service) DeleteSigningKey(ctx context.Context, kid string) error {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	if err := s.store.DeleteSigningKey(ctx, kid); err != nil {
		return fmt.Errorf("oauth service: delete signing key: %w", err)
	}
	if err := s.reloadSigningKeysLocked(ctx); err != nil {
		return err
	}
	s.logger.Info("oauth signing key deleted", "kid", kid)
	return nil
}

// loadOAuthApp looks up an OAuth-enabled app by clientID, mapping unknown or
// OAuth-disabled apps to app.ErrOAuthNotEnabled consistently across every grant
// and client-auth path.
func (s *Service) loadOAuthApp(ctx context.Context, op, clientID string) (*app.App, error) {
	if clientID == "" {
		return nil, app.ErrOAuthNotEnabled
	}
	a, err := s.apps.GetByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return nil, app.ErrOAuthNotEnabled
		}
		return nil, fmt.Errorf("%s: get app: %w", op, err)
	}
	if !a.OAuthEnabled {
		return nil, app.ErrOAuthNotEnabled
	}
	return a, nil
}

// enforceAccessPolicy applies the app's per-app access policy to a token
// grant. When u is non-nil it is reused directly, avoiding a second user lookup.
func (s *Service) enforceAccessPolicy(ctx context.Context, a *app.App, userID string, u *user.User, clientIP string) error {
	if a.Policy().IsEmpty() {
		return nil
	}

	if u == nil {
		var err error
		u, err = s.users.GetByID(ctx, userID)
		if err != nil {
			return fmt.Errorf("oauth enforce access policy: load user: %w", err)
		}
	}
	decision, err := s.apps.EvaluateAccess(ctx, a, userID, u.IsAdmin, clientIP, time.Now())
	if err != nil {
		return fmt.Errorf("oauth enforce access policy: evaluate: %w", err)
	}
	if !decision.Allowed {
		return &PolicyDenialError{
			AppSlug:  a.Slug,
			Reason:   decision.Reason,
			UserID:   u.ID,
			Username: u.Username,
		}
	}
	return nil
}

// Authorize validates an authorization request and creates a code. clientIP is
// the browser's address at the authorization endpoint (used only by the app's
// access policy). resource is the RFC 8707 resource indicator, or "" when the
// client requested none.
//
// It returns a *PolicyDenialError when the app's group, role, CIDR, admin-only,
// hour or day rules refuse the user, ErrInvalidScope when the request escalates
// beyond the app's scope registry, and ErrInvalidTarget when a resource
// indicator is not one of the app's registered audiences. No code is created in
// any of those cases.
func (s *Service) Authorize(ctx context.Context, clientID, redirectURI, scope, resource, state, nonce, codeChallenge, codeChallengeMethod string, sessionCreatedAt time.Time, userID, clientIP string) (*Code, error) {
	// Look up app by clientID.
	a, err := s.loadOAuthApp(ctx, "oauth authorize", clientID)
	if err != nil {
		return nil, err
	}

	// Validate redirectURI: exact string match against registered URIs.
	if err := checkRedirectURI(a, redirectURI); err != nil {
		return nil, err
	}

	// Check that the user has access to this app.
	hasAccess, err := s.apps.HasAccess(ctx, userID, a.ID)
	if err != nil {
		return nil, fmt.Errorf("oauth authorize: check access: %w", err)
	}
	if !hasAccess {
		return nil, fmt.Errorf("oauth authorize: user does not have access to this application")
	}

	// Per-app access policy. Only apps that define a policy incur the extra
	// assignment and user lookups; an app with no policy authorizes exactly as
	// before. A malformed stored rule or an unparseable client address fails
	// closed with the same opaque error the client sees for any other policy
	// denial.
	if err := s.enforceAccessPolicy(ctx, a, userID, nil, clientIP); err != nil {
		return nil, err
	}

	// Validate PKCE parameters per RFC 7636 §4.3.
	var pkceMethod PKCEMethod
	if codeChallenge != "" {
		switch codeChallengeMethod {
		case string(PKCEMethodS256):
			pkceMethod = PKCEMethodS256
		case "":
			// method omitted; default to S256 per RFC 7636 §4.3 ABNF default.
			pkceMethod = PKCEMethodS256
		default:
			// "plain" and anything else are rejected (OAuth 2.1 drops "plain":
			// the challenge is verifier-equivalent when observed in the
			// authorize request URL).
			return nil, fmt.Errorf("oauth authorize: unsupported code_challenge_method: %w", ErrPKCEVerificationFailed)
		}
		// Validate challenge length per RFC 7636 §4.2: S256 challenges are
		// always BASE64URL(SHA256(verifier)) = 43 chars.
		if len(codeChallenge) != 43 {
			return nil, fmt.Errorf("oauth authorize: S256 code_challenge must be 43 characters: %w", ErrPKCEVerificationFailed)
		}
	}

	// Normalize the requested scope and enforce the app's scope registry.
	// An empty registry keeps the pre-registry behaviour: whatever the client
	// asks for is granted, and an absent scope still means openid.
	scope = normalizeScope(scope)
	if scope == "" {
		scope = "openid"
	}
	if err := validateRequestedScopes(a.AllowedScopes, scope); err != nil {
		return nil, err
	}

	// Validate the RFC 8707 resource indicator. The granted audience is stored
	// with the code so the token endpoint cannot issue a token for a different
	// one.
	grantedResource, err := resolveResource(a, resource)
	if err != nil {
		return nil, err
	}

	// Create authorization code.
	code := &Code{
		AppID:               a.ID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		Scopes:              scope,
		Resource:            grantedResource,
		Nonce:               nonce,
		AuthTime:            sessionCreatedAt.UTC(),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: pkceMethod,
		ExpiresAt:           time.Now().UTC().Add(authCodeTTL),
	}
	if err := s.store.CreateCode(ctx, code); err != nil {
		return nil, fmt.Errorf("oauth authorize: create code: %w", err)
	}

	return code, nil
}

// checkRedirectURI reports whether redirectURI is one of the app's registered
// redirect URIs. The comparison is an exact string match: no prefix, suffix, or
// wildcard matching.
func checkRedirectURI(a *app.App, redirectURI string) error {
	for _, uri := range a.RedirectURIs {
		if uri == redirectURI {
			return nil
		}
	}
	return app.ErrRedirectURIMismatch
}

// ValidateClientRedirectURI performs the client and redirect_uri checks of
// Authorize without issuing a code. It exists for authorization requests that
// must be answered before a session is resolved (prompt=none, which may not
// show UI): an error response may only be redirected to a redirect_uri that is
// registered to the client, otherwise the endpoint would be an open
// redirector. The sentinels are the same ones Authorize returns.
func (s *Service) ValidateClientRedirectURI(ctx context.Context, clientID, redirectURI string) error {
	a, err := s.loadOAuthApp(ctx, "oauth validate client redirect", clientID)
	if err != nil {
		return err
	}
	return checkRedirectURI(a, redirectURI)
}
