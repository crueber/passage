package user

import (
	"context"
	"net/http"
	"strings"
)

// mfaRequired reports whether the instance enforces a second factor for every
// account. An explicit settings-store value wins over the auth.require_mfa
// config/env default, which is what makes the admin checkbox authoritative
// once it has been saved.
func (h *Handler) mfaRequired(ctx context.Context) bool {
	if h.settings != nil {
		if raw, err := h.settings.Get(ctx, SettingRequireMFA); err == nil {
			return strings.EqualFold(strings.TrimSpace(raw), "true")
		}
	}
	return h.cfg.Auth.RequireMFA
}

// RequireMFA is the global "require two-factor authentication" gate.
//
// When the policy is on, a signed-in user without a completed enrollment is
// sent to /mfa/setup for every route this middleware is mounted on. The gate
// deliberately lives on the session, not on a pending token: enrolling
// satisfies it immediately in the same session, with no extra state to keep in
// sync.
//
// It must NOT be mounted on /mfa/*, /logout, /static/*, or the security page
// (/passkeys) — those are the routes a user needs in order to satisfy it.
// run.go puts it on the app routes and the admin routes only.
func (h *Handler) RequireMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.mfa == nil || !h.mfaRequired(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		u, ok := h.userCtx(r.Context())
		if !ok || u == nil {
			// No authenticated user: an outer middleware owns that decision.
			next.ServeHTTP(w, r)
			return
		}

		enabled, err := h.mfa.Enabled(r.Context(), u.ID)
		if err != nil {
			// Fail open, loudly. The MFA tables share the SQLite file with the
			// sessions RequireSession just validated, so an error here means the
			// database is in trouble — and a policy check is not worth locking
			// every operator out of an auth proxy. The policy still applies on
			// the next request.
			h.logger.Warn("mfa gate: enrollment check failed", "user_id", u.ID, "error", err)
			next.ServeHTTP(w, r)
			return
		}
		if !enabled {
			http.Redirect(w, r, "/mfa/setup?required=1", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
