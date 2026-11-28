// Package csrf provides synchronizer-token CSRF protection for Passage.
//
// Two middleware variants are provided:
//
//   - ProtectAuthenticated: for routes that require a session. The session
//     token (from the session cookie) is used as the HMAC signing key so the
//     CSRF token is inherently session-bound.
//
//   - ProtectAnonymous: for unauthenticated routes (login, register, reset,
//     setup). Uses the double-submit cookie pattern: a random value stored in
//     a non-HttpOnly cookie is mixed with a server-side secret (cfg.CSRF.Key,
//     generated at startup when not configured) as the signing key, so tokens
//     are always bound to a secret the client cannot choose.
//
// Both variants use the same token format and validation logic.
package csrf

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"time"
)

// contextKey is an unexported type for context keys in this package to prevent
// collisions with keys from other packages.
type contextKey int

const (
	tokenContextKey contextKey = iota
)

const (
	// CookieName is the base CSRF cookie name used by ProtectAnonymous.
	// It is deliberately NOT HttpOnly so that htmx can read it if needed.
	// When secure cookies are enabled the name is prefixed with __Host-
	// (see cookieName) to block sibling-subdomain cookie tossing.
	CookieName = "passage_csrf"

	// FieldName is the hidden form field name that carries the CSRF token.
	FieldName = "_csrf"

	// HeaderName is the HTTP header the middleware also checks (for htmx requests).
	HeaderName = "HX-CSRF-Token"

	// tokenTTL is the maximum age of a CSRF token.
	tokenTTL = 4 * time.Hour

	// tokenPayloadLen is nonce(16) + timestamp(8) + HMAC-SHA256(32).
	tokenPayloadLen = 56
)

// GenerateToken generates a new CSRF token string HMAC-signed with signingKey.
//
// signingKey should be either:
//   - the session token value (authenticated routes), or
//   - the CSRF cookie value mixed with the server secret (anonymous routes).
//
// Token wire format (base64url-encoded): nonce(16) || timestamp(8) || HMAC-SHA256(32)
func GenerateToken(signingKey string) (string, error) {
	var payload [tokenPayloadLen]byte
	if _, err := rand.Read(payload[:16]); err != nil {
		return "", fmt.Errorf("csrf: generate nonce: %w", err)
	}
	binary.BigEndian.PutUint64(payload[16:24], uint64(time.Now().Unix()))
	copy(payload[24:], hmacSign(signingKey, payload[:24]))
	return base64.RawURLEncoding.EncodeToString(payload[:]), nil
}

// ValidateToken verifies that submitted is a valid, unexpired CSRF token signed
// with signingKey. Returns a descriptive error if validation fails.
func ValidateToken(signingKey, submitted string) error {
	if submitted == "" {
		return fmt.Errorf("csrf: empty token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(submitted)
	if err != nil || len(payload) != tokenPayloadLen {
		return fmt.Errorf("csrf: malformed token")
	}

	ts := int64(binary.BigEndian.Uint64(payload[16:24]))
	if time.Since(time.Unix(ts, 0)) > tokenTTL {
		return fmt.Errorf("csrf: token expired")
	}

	expectedMAC := hmacSign(signingKey, payload[:24])
	if !hmac.Equal(payload[24:], expectedMAC) {
		return fmt.Errorf("csrf: invalid token")
	}
	return nil
}

// TokenFromContext retrieves the CSRF token string stored in ctx by the middleware.
// Returns an empty string if no token is present (e.g. context not yet populated).
func TokenFromContext(ctx context.Context) string {
	v, _ := ctx.Value(tokenContextKey).(string)
	return v
}

// withToken returns a copy of ctx with token stored under the CSRF context key.
func withToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenContextKey, token)
}

// hmacSign returns a 32-byte HMAC-SHA256 of data keyed by key.
func hmacSign(key string, data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	return mac.Sum(nil)
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// serveWithCSRF enforces token validation on non-safe methods and injects a
// fresh CSRF token into the request context for both safe and valid non-safe
// requests.
func serveWithCSRF(w http.ResponseWriter, r *http.Request, next http.Handler, signingKey string) {
	if !isSafeMethod(r.Method) {
		submitted := r.Header.Get(HeaderName)
		if submitted == "" {
			// PostFormValue ignores URL query parameters so CSRF tokens cannot
			// be passed in query strings (and leaked via Referer/logs).
			submitted = r.PostFormValue(FieldName)
		}
		if err := ValidateToken(signingKey, submitted); err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
	}

	tok, err := GenerateToken(signingKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	r = r.WithContext(withToken(r.Context(), tok))
	next.ServeHTTP(w, r)
}

// ProtectAuthenticated is a chi middleware for routes that require a valid session.
//
// On safe methods (GET, HEAD, OPTIONS): generates a CSRF token signed with the
// session token and stores it in the request context via withToken.
//
// On state-changing methods (POST, PUT, PATCH, DELETE): validates the submitted
// CSRF token (from the HX-CSRF-Token header or _csrf POST body field) against
// the session token. Returns 403 Forbidden on failure.
//
// sessionCookieName must match the name used to set the session cookie.
func ProtectAuthenticated(sessionCookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionToken := ""
			if c, err := r.Cookie(sessionCookieName); err == nil {
				sessionToken = c.Value
			}
			if sessionToken == "" {
				// No session cookie present — cannot generate a session-bound token.
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			serveWithCSRF(w, r, next, sessionToken)
		})
	}
}

// ProtectAnonymous is a chi middleware for unauthenticated form routes (login,
// register, reset, setup) where no session token exists yet.
//
// It uses the double-submit cookie pattern: a random value is stored in a
// non-HttpOnly cookie mixed with the server-side cfgKey (generated at startup
// when the operator has not configured one). The cfgKey is never transmitted
// to the client.
//
// On safe methods: issues/refreshes the CSRF cookie if absent and stores a
// generated token in the request context.
//
// On state-changing methods: validates the submitted token against the signing
// key derived from the CSRF cookie. Returns 403 Forbidden on failure.
// A request that arrives with no CSRF cookie is rejected immediately without
// setting a cookie.
func ProtectAnonymous(cfgKey string, cookieSecure bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signingKey := csrfCookieKey(r, cookieName(cookieSecure), cfgKey)
			if signingKey == "" {
				if !isSafeMethod(r.Method) {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				// No CSRF cookie yet on a safe request — issue one.
				raw := make([]byte, 32)
				if _, err := rand.Read(raw); err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				cookieVal := base64.RawURLEncoding.EncodeToString(raw)
				if cfgKey != "" {
					signingKey = cookieVal + "." + cfgKey
				} else {
					signingKey = cookieVal
				}
				http.SetCookie(w, &http.Cookie{
					Name:     cookieName(cookieSecure),
					Value:    cookieVal,
					Path:     "/",
					HttpOnly: false,
					Secure:   cookieSecure,
					SameSite: http.SameSiteLaxMode,
					MaxAge:   int(tokenTTL.Seconds()),
				})
			}

			serveWithCSRF(w, r, next, signingKey)
		})
	}
}

// cookieName returns the CSRF cookie name, applying the __Host- prefix when
// secure cookies are enabled. The prefix requires Secure, no Domain, and
// Path=/ — all of which ProtectAnonymous sets.
func cookieName(secure bool) string {
	if secure {
		return "__Host-" + CookieName
	}
	return CookieName
}

// csrfCookieKey returns the effective signing key from the CSRF cookie.
// The cookie stores only the random value; cfgKey is appended server-side
// if non-empty. Returns empty string if the CSRF cookie is absent or empty.
func csrfCookieKey(r *http.Request, name, cfgKey string) string {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return ""
	}
	if cfgKey != "" {
		return c.Value + "." + cfgKey
	}
	return c.Value
}
