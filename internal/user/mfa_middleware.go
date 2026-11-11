package user

import (
	"context"
	"net/http"

	"github.com/crueber/passage/internal/config"
)

// mfaRequired reports whether the instance enforces a second factor for every
// account. An explicit auth.require_mfa from the config file or environment
// wins; otherwise the saved admin setting does; otherwise the config default.
func (h *Handler) mfaRequired(ctx context.Context) bool {
	if h.settings == nil {
		return h.cfg.Auth.RequireMFA
	}
	raw, err := h.settings.Get(ctx, SettingRequireMFA)
	return config.BoolSetting(h.cfg.Auth.RequireMFASet, h.cfg.Auth.RequireMFA, raw, err == nil)
}

// MFABlocked reports whether the global policy currently requires this user to
// enroll before using the instance. It is the single definition of the policy:
// RequireMFA uses it for Passage's own routes and forward-auth uses it for
// upstream apps, so an un-enrolled user cannot reach either.
//
// It fails open on a store error, loudly: the MFA tables share the SQLite file
// with the sessions that were just validated, so an error here means the
// database is in trouble, and a policy check is not worth locking every
// operator out of an auth proxy. The policy still applies on the next request.
func (h *Handler) MFABlocked(ctx context.Context, userID string) bool {
	if h.mfa == nil || !h.mfaRequired(ctx) {
		return false
	}
	enabled, err := h.mfa.Enabled(ctx, userID)
	if err != nil {
		h.logger.Warn("mfa policy: enrollment check failed", "user_id", userID, "error", err)
		return false
	}
	return !enabled
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

		if h.MFABlocked(r.Context(), u.ID) {
			http.Redirect(w, r, "/mfa/setup?required=1", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}
