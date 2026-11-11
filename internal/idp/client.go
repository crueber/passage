// Package idp implements sign-in through upstream OIDC/OAuth identity
// providers and links the resulting identity to a local Passage account.
//
// It is deliberately small: net/http for the protocol, and
// github.com/golang-jwt/jwt/v5 for id_token verification. No vendor SDK.
package idp

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/crueber/passage/internal/config"
)

// errJWKSKeyNotFound marks a token whose kid is not in the cached JWKS. It is
// the only verification failure worth a cache refresh: the provider may have
// rotated its signing key.
var errJWKSKeyNotFound = errors.New("idp: JWKS key not found")

// Cache TTLs. Discovery documents and JWKS rotate rarely; caching keeps one
// login from making three upstream requests. A rotated signing key becomes
// visible within one TTL, and a hard verification failure refreshes the cache
// once before giving up (see verifyIDToken).
const (
	defaultCacheTTL = 15 * time.Minute
	maxResponseBody = 1 << 20 // 1 MiB
)

// Provider is the runtime form of one configured upstream provider.
type Provider struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	AutoCreate   bool
}

// Providers converts configured providers into runtime values, normalising the
// issuer (trailing slash removed) and defaulting the scopes. The caller has
// already validated the configuration.
func Providers(cfgs []config.ProviderConfig) []*Provider {
	out := make([]*Provider, 0, len(cfgs))
	for _, p := range cfgs {
		scopes := append([]string(nil), p.Scopes...)
		if len(scopes) == 0 {
			// openid is required to receive an id_token; email is required to
			// link to an existing account by address.
			scopes = config.DefaultProviderScopes()
		}
		out = append(out, &Provider{
			Name:         p.Name,
			Issuer:       strings.TrimRight(p.Issuer, "/"),
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			Scopes:       scopes,
			AutoCreate:   p.AutoCreate,
		})
	}
	return out
}

// Discovery is the subset of the OIDC discovery document Passage needs.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Identity is the information extracted from a verified id_token. It carries
// only the claims the linking rules need; no access token is retained.
type Identity struct {
	Subject           string
	Email             string
	EmailVerified     bool
	Name              string
	PreferredUsername string
}

type discoveryEntry struct {
	doc     *Discovery
	expires time.Time
}

type jwksEntry struct {
	keys    []rsaKey
	expires time.Time
}

type rsaKey struct {
	kid string
	key *rsa.PublicKey
}

// Client performs discovery, code exchange, and id_token verification. It is
// safe for concurrent use. It holds no request-scoped state.
type Client struct {
	http *http.Client
	now  func() time.Time
	ttl  time.Duration

	mu        sync.Mutex
	discovery map[string]discoveryEntry
	jwks      map[string]jwksEntry
}

// NewClient returns a Client using hc. A nil hc gets a default client with a
// bounded timeout: an unreachable provider must not hold a login request open
// indefinitely.
func NewClient(hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		http:      hc,
		now:       time.Now,
		ttl:       defaultCacheTTL,
		discovery: make(map[string]discoveryEntry),
		jwks:      make(map[string]jwksEntry),
	}
}

// Discover fetches (or returns a cached copy of) the provider's discovery
// document and verifies that it belongs to the configured issuer.
func (c *Client) Discover(ctx context.Context, issuer string) (*Discovery, error) {
	issuer = strings.TrimRight(issuer, "/")

	c.mu.Lock()
	entry, ok := c.discovery[issuer]
	c.mu.Unlock()
	if ok && c.now().Before(entry.expires) {
		return entry.doc, nil
	}

	var doc Discovery
	if err := c.getJSON(ctx, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("idp discovery: %w", err)
	}

	// OIDC Discovery §4.3: the issuer in the document must match the issuer
	// used to build the request, exactly.
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return nil, fmt.Errorf("idp discovery: issuer mismatch: document names %q, configured %q", doc.Issuer, issuer)
	}
	for name, endpoint := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"jwks_uri":               doc.JWKSURI,
	} {
		if err := requireHTTPSURL(endpoint); err != nil {
			return nil, fmt.Errorf("idp discovery: %s: %w", name, err)
		}
	}

	c.mu.Lock()
	c.discovery[issuer] = discoveryEntry{doc: &doc, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return &doc, nil
}

// AuthCodeURL builds the authorization request URL with state, nonce, and a
// PKCE S256 challenge.
func AuthCodeURL(doc *Discovery, p *Provider, redirectURI, state, nonce, challenge string) (string, error) {
	u, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("idp: parse authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(p.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// PKCEChallenge returns the S256 challenge for a verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
}

// Exchange redeems an authorization code for an id_token at the provider's
// token endpoint, authenticating with client_secret_basic and sending the PKCE
// verifier. It returns the raw id_token for verification; neither the code nor
// the token is ever logged.
func (c *Client) Exchange(ctx context.Context, p *Provider, tokenEndpoint, code, verifier, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("idp exchange: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(p.ClientID, p.ClientSecret)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("idp exchange: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return "", fmt.Errorf("idp exchange: read response: %w", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("idp exchange: decode response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The OAuth error code is safe to surface; the description and body are
		// not, so they stay out of the error and the logs.
		return "", fmt.Errorf("idp exchange: token endpoint returned status %d (error %q)", resp.StatusCode, tr.Error)
	}
	if tr.IDToken == "" {
		return "", errors.New("idp exchange: token response has no id_token")
	}
	return tr.IDToken, nil
}

// VerifyIDToken verifies the id_token's RS256 signature against the provider's
// JWKS and its issuer, audience, expiry, and nonce. It returns the claims the
// linking rules need.
func (c *Client) VerifyIDToken(ctx context.Context, p *Provider, jwksURI, rawToken, nonce string) (*Identity, error) {
	claims := jwtlib.MapClaims{}
	opts := []jwtlib.ParserOption{
		jwtlib.WithValidMethods([]string{"RS256"}),
		jwtlib.WithIssuer(p.Issuer),
		jwtlib.WithAudience(p.ClientID),
		jwtlib.WithExpirationRequired(),
		jwtlib.WithLeeway(30 * time.Second),
	}

	token, err := jwtlib.ParseWithClaims(rawToken, claims, c.keyfunc(ctx, jwksURI, false), opts...)
	if err != nil && errors.Is(err, errJWKSKeyNotFound) {
		// A provider that rotated its signing key is the common benign cause of
		// an unknown kid. Refresh once and retry before rejecting the login.
		claims = jwtlib.MapClaims{}
		token, err = jwtlib.ParseWithClaims(rawToken, claims, c.keyfunc(ctx, jwksURI, true), opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("idp: verify id_token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("idp: verify id_token: token is not valid")
	}

	gotNonce, _ := claims["nonce"].(string)
	if gotNonce == "" || subtle.ConstantTimeCompare([]byte(gotNonce), []byte(nonce)) != 1 {
		return nil, errors.New("idp: verify id_token: nonce mismatch")
	}

	subject, _ := claims["sub"].(string)
	subject = strings.TrimSpace(subject)
	if subject == "" || len(subject) > 255 {
		return nil, errors.New("idp: verify id_token: missing or invalid subject")
	}

	emailAddr, _ := claims["email"].(string)
	emailAddr = strings.ToLower(strings.TrimSpace(emailAddr))

	name, _ := claims["name"].(string)
	preferred, _ := claims["preferred_username"].(string)

	return &Identity{
		Subject:           subject,
		Email:             emailAddr,
		EmailVerified:     claimBool(claims, "email_verified"),
		Name:              strings.TrimSpace(name),
		PreferredUsername: strings.TrimSpace(preferred),
	}, nil
}

// claimBool reads a boolean claim that providers may encode as a bool or as a
// string ("true"/"false"). Anything else is false: an unparseable verification
// claim must never link accounts by email.
func claimBool(claims jwtlib.MapClaims, name string) bool {
	switch v := claims[name].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func (c *Client) keyfunc(ctx context.Context, jwksURI string, forceRefresh bool) jwtlib.Keyfunc {
	return func(t *jwtlib.Token) (any, error) {
		if _, ok := t.Method.(*jwtlib.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("idp: unexpected signing method %q", t.Method.Alg())
		}
		keys, err := c.keys(ctx, jwksURI, forceRefresh)
		if err != nil {
			return nil, err
		}
		kid, _ := t.Header["kid"].(string)
		for _, k := range keys {
			if kid == "" || k.kid == kid {
				return k.key, nil
			}
		}
		return nil, fmt.Errorf("%w: kid %q", errJWKSKeyNotFound, kid)
	}
}

// keys fetches and caches the provider's RSA signing keys.
func (c *Client) keys(ctx context.Context, jwksURI string, forceRefresh bool) ([]rsaKey, error) {
	c.mu.Lock()
	entry, ok := c.jwks[jwksURI]
	c.mu.Unlock()
	if ok && !forceRefresh && c.now().Before(entry.expires) {
		return entry.keys, nil
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := c.getJSON(ctx, jwksURI, &doc); err != nil {
		return nil, fmt.Errorf("idp: fetch JWKS: %w", err)
	}

	keys := make([]rsaKey, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue
		}
		key, err := parseRSAKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys = append(keys, rsaKey{kid: k.Kid, key: key})
	}
	if len(keys) == 0 {
		return nil, errors.New("idp: JWKS contains no usable RS256 keys")
	}

	c.mu.Lock()
	c.jwks[jwksURI] = jwksEntry{keys: keys, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return keys, nil
}

func parseRSAKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("empty modulus or exponent")
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e < 3 {
		return nil, errors.New("invalid exponent")
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	if key.Size()*8 < 2048 {
		return nil, fmt.Errorf("key is %d bits; RS256 requires at least 2048", key.Size()*8)
	}
	return key, nil
}

// getJSON performs a bounded GET and decodes a JSON body. Error messages carry
// the URL and status only — never a response body, which may contain a token.
func (c *Client) getJSON(ctx context.Context, rawURL string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request %s: status %d", rawURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return fmt.Errorf("read %s: %w", rawURL, err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode %s: %w", rawURL, err)
	}
	return nil
}

// requireHTTPSURL rejects anything that is not an absolute https URL. The
// browser, and Passage, will follow these endpoints; a plaintext or relative
// value is a red flag, not a fallback.
func requireHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("must use https, got scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("must include a host")
	}
	return nil
}
