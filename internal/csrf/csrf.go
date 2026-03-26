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
//     a non-HttpOnly cookie is the signing key, optionally mixed with a
//     server-side secret (cfg.CSRF.Key) for defence-in-depth.
//
// Both variants use the same token format and validation logic.
package csrf

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	// CookieName is the CSRF cookie name used by ProtectAnonymous.
	// It is deliberately NOT HttpOnly so that htmx can read it if needed.
	CookieName = "passage_csrf"

	// FieldName is the hidden form field name that carries the CSRF token.
	FieldName = "_csrf"

	// HeaderName is the HTTP header the middleware also checks (for htmx requests).
	HeaderName = "HX-CSRF-Token"

	// tokenTTL is the maximum age of a CSRF token.
	tokenTTL = 4 * time.Hour
)

// GenerateToken generates a new CSRF token string HMAC-signed with signingKey.
//
// signingKey should be either:
//   - the session token value (authenticated routes), or
//   - the CSRF cookie value (unauthenticated double-submit routes).
//
// Token wire format (base64url-encoded): nonce(16) || timestamp(8) || HMAC-SHA256(32)
func GenerateToken(signingKey string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("csrf: generate nonce: %w", err)
	}

	now := time.Now().Unix()
	ts := make([]byte, 8)
	ts[0] = byte(now >> 56)
	ts[1] = byte(now >> 48)
	ts[2] = byte(now >> 40)
	ts[3] = byte(now >> 32)
	ts[4] = byte(now >> 24)
	ts[5] = byte(now >> 16)
	ts[6] = byte(now >> 8)
	ts[7] = byte(now)

	mac := hmacSign(signingKey, append(nonce, ts...))
	payload := append(append(nonce, ts...), mac...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

// ValidateToken verifies that submitted is a valid, unexpired CSRF token signed
// with signingKey. Returns a descriptive error if validation fails.
func ValidateToken(signingKey, submitted string) error {
	if submitted == "" {
		return fmt.Errorf("csrf: empty token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(submitted)
	if err != nil || len(payload) < 56 { // 16 nonce + 8 ts + 32 mac
		return fmt.Errorf("csrf: malformed token")
	}

	nonce := payload[:16]
	tsBytes := payload[16:24]
	submittedMAC := payload[24:56]

	// Reconstruct the timestamp from big-endian bytes.
	var ts int64
	for i := 0; i < 8; i++ {
		ts = (ts << 8) | int64(tsBytes[i])
	}
	if time.Since(time.Unix(ts, 0)) > tokenTTL {
		return fmt.Errorf("csrf: token expired")
	}

	expectedMAC := hmacSign(signingKey, append(nonce, tsBytes...))
	if !hmac.Equal(submittedMAC, expectedMAC) {
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

// ProtectAuthenticated is a chi middleware for routes that require a valid session.
//
// On safe methods (GET, HEAD, OPTIONS): generates a CSRF token signed with the
// session token and stores it in the request context via withToken.
//
// On state-changing methods (POST, PUT, PATCH, DELETE): validates the submitted
// CSRF token (from the _csrf form field or HX-CSRF-Token header) against the
// session token. Returns 403 Forbidden on failure.
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

			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				tok, err := GenerateToken(sessionToken)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				r = r.WithContext(withToken(r.Context(), tok))
				next.ServeHTTP(w, r)

			default:
				submitted := r.FormValue(FieldName)
				if submitted == "" {
					submitted = r.Header.Get(HeaderName)
				}
				if err := ValidateToken(sessionToken, submitted); err != nil {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				// Regenerate a fresh token for the response so the page can
				// render a valid token for the next request.
				tok, err := GenerateToken(sessionToken)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				r = r.WithContext(withToken(r.Context(), tok))
				next.ServeHTTP(w, r)
			}
		})
	}
}

// ProtectAnonymous is a chi middleware for unauthenticated form routes (login,
// register, reset, setup) where no session token exists yet.
//
// It uses the double-submit cookie pattern: a random value is stored in a
// non-HttpOnly cookie (passage_csrf). If cfgKey is non-empty, it is appended
// server-side to the cookie value to derive the HMAC signing key, binding the
// token to a server-side secret for additional protection against subdomain
// attacks. The cfgKey is never transmitted to the client.
//
// On safe methods: issues/refreshes the CSRF cookie if absent and stores a
// generated token in the request context.
//
// On state-changing methods: validates the submitted token against the signing
// key derived from the CSRF cookie. Returns 403 Forbidden on failure.
// A request that arrives with no CSRF cookie is rejected — the middleware
// fails closed, the same as a request with a wrong token.
func ProtectAnonymous(cfgKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			signingKey := csrfCookieKey(r, cfgKey)
			if signingKey == "" {
				// No CSRF cookie yet — generate a new random value and set the cookie.
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
				// Set the CSRF cookie with only the random value — the cfgKey is
				// a server-side secret and must never be transmitted to the client.
				http.SetCookie(w, &http.Cookie{
					Name:     CookieName,
					Value:    cookieVal,
					Path:     "/",
					HttpOnly: false,
					SameSite: http.SameSiteLaxMode,
					MaxAge:   int(tokenTTL.Seconds()),
				})
			}

			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				tok, err := GenerateToken(signingKey)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				r = r.WithContext(withToken(r.Context(), tok))
				next.ServeHTTP(w, r)

			default:
				submitted := r.FormValue(FieldName)
				if submitted == "" {
					submitted = r.Header.Get(HeaderName)
				}
				if err := ValidateToken(signingKey, submitted); err != nil {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				tok, err := GenerateToken(signingKey)
				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
				r = r.WithContext(withToken(r.Context(), tok))
				next.ServeHTTP(w, r)
			}
		})
	}
}

// csrfCookieKey returns the effective signing key from the CSRF cookie.
// The cookie stores only the random value; cfgKey is appended server-side
// if non-empty. Returns empty string if the CSRF cookie is absent or empty.
func csrfCookieKey(r *http.Request, cfgKey string) string {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	if cfgKey != "" {
		return c.Value + "." + cfgKey
	}
	return c.Value
}
