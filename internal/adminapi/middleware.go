package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/crueber/passage/internal/authlog"
)

// authenticator validates a presented bearer token. Defined at the consumer
// boundary; backed by *Service in run.go.
type authenticator interface {
	Authenticate(ctx context.Context, presented string) (*Token, error)
}

// authEventRecorder records failed bearer authentication in the security log.
// Defined at the consumer boundary; backed by *authlog.Recorder in run.go. A
// nil recorder disables event recording.
type authEventRecorder interface {
	Record(ctx context.Context, e authlog.Event)
}

// tokenKey is the context key holding the authenticated token.
type tokenKey struct{}

// TokenFromContext returns the token that authenticated the request.
func TokenFromContext(ctx context.Context) (*Token, bool) {
	t, ok := ctx.Value(tokenKey{}).(*Token)
	return t, ok
}

// withToken returns a context carrying the authenticated token.
func withToken(ctx context.Context, t *Token) context.Context {
	return context.WithValue(ctx, tokenKey{}, t)
}

// RequireToken returns middleware that requires a valid API token in the
// Authorization header. Every rejection is a 401 with
// `WWW-Authenticate: Bearer` — the response never distinguishes a missing
// header, an unknown token, and a revoked one.
func RequireToken(auth authenticator, recorder authEventRecorder, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented, ok := bearerToken(r)
			if !ok {
				recordAuthFailure(r, recorder, "missing or malformed authorization header")
				logger.Warn("adminapi: rejected request", "reason", "missing bearer token", "path", r.URL.Path, "ip", authlog.ClientIP(r))
				writeUnauthorized(w)
				return
			}

			t, err := auth.Authenticate(r.Context(), presented)
			if err != nil {
				if !errors.Is(err, ErrTokenNotFound) {
					logger.Error("adminapi: authenticate token", "path", r.URL.Path, "error", err)
					writeError(w, http.StatusInternalServerError, "internal server error")
					return
				}
				recordAuthFailure(r, recorder, "invalid or revoked token")
				logger.Warn("adminapi: rejected request", "reason", "invalid or revoked token", "path", r.URL.Path, "ip", authlog.ClientIP(r))
				writeUnauthorized(w)
				return
			}

			next.ServeHTTP(w, r.WithContext(withToken(r.Context(), t)))
		})
	}
}

// bearerToken extracts the token from an `Authorization: Bearer <token>`
// header. The scheme is compared case-insensitively, as RFC 7235 requires.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "bearer "
	header := r.Header.Get("Authorization")
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// writeUnauthorized writes the single 401 body used for every rejected
// credential. The plaintext token is never echoed or logged.
func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

// recordAuthFailure writes a failed bearer authentication to the security log.
// Recording is best-effort by design (see authlog.Recorder.Record).
func recordAuthFailure(r *http.Request, recorder authEventRecorder, detail string) {
	if recorder == nil {
		return
	}
	recorder.Record(r.Context(), authlog.Event{
		Event:     authlog.EventAPIAuthFailure,
		Outcome:   authlog.OutcomeFailure,
		IP:        authlog.ClientIP(r),
		UserAgent: r.UserAgent(),
		Detail:    detail,
	})
}
