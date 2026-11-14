package admin

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/oauth"
)

// signingKeyManager is the admin-facing view of the OIDC signing keyring.
// Defined at the consumer boundary; backed by *oauth.Service in run.go.
type signingKeyManager interface {
	ListSigningKeys(ctx context.Context) ([]*oauth.SigningKey, error)
	RotateSigningKey(ctx context.Context) (*oauth.SigningKey, error)
	RetireSigningKey(ctx context.Context, kid string) error
	DeleteSigningKey(ctx context.Context, kid string) error
}

// signingKeyRow is one row of the signing-keys table. It carries only metadata:
// private key material never reaches a template.
type signingKeyRow struct {
	KID       string
	CreatedAt time.Time
	RetiredAt *time.Time
	// Current marks the key that signs new id_tokens.
	Current bool
	// CanRetire is false for the only non-retired key, because retiring it
	// would leave the issuer unable to sign.
	CanRetire bool
}

// signingKeysData is the template data for the signing keys page.
type signingKeysData struct {
	basePage
	Keys []signingKeyRow
}

// GetSigningKeys renders the OIDC signing key history.
func (h *Handler) GetSigningKeys(w http.ResponseWriter, r *http.Request) {
	h.renderSigningKeys(w, r, h.base(r, "signing-keys"))
}

// PostRotateSigningKey generates a new RSA key and makes it current. The
// previous keys stay active, so id_tokens they signed keep verifying until
// they expire — that is the point of kid history.
func (h *Handler) PostRotateSigningKey(w http.ResponseWriter, r *http.Request) {
	key, err := h.signingKeys.RotateSigningKey(r.Context())
	if err != nil {
		h.logger.Error("admin: rotate oauth signing key", "error", err)
		h.renderSigningKeys(w, r, h.baseFlash(r, "signing-keys", &Flash{
			Type:    "error",
			Message: "Failed to generate a signing key. Please try again.",
		}))
		return
	}

	// Audit the new kid; the private key is never logged.
	h.logAudit(r, AuditActionOAuthKeyRotate, "oauth_signing_key", key.KID, "")
	http.Redirect(w, r, "/admin/signing-keys?flash=key-rotated", http.StatusFound)
}

// PostRetireSigningKey stops a key being served and accepted. The last active
// key is refused.
func (h *Handler) PostRetireSigningKey(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")

	err := h.signingKeys.RetireSigningKey(r.Context(), kid)
	switch {
	case err == nil:
		h.logAudit(r, AuditActionOAuthKeyRetire, "oauth_signing_key", kid, "")
		http.Redirect(w, r, "/admin/signing-keys?flash=key-retired", http.StatusFound)
	case errors.Is(err, oauth.ErrSigningKeyLast):
		h.renderSigningKeys(w, r, h.baseFlash(r, "signing-keys", &Flash{
			Type:    "error",
			Message: "This is the only active signing key. Rotate first, then retire it.",
		}))
	case errors.Is(err, oauth.ErrSigningKeyNotFound):
		http.Redirect(w, r, "/admin/signing-keys?flash=error", http.StatusFound)
	default:
		h.logger.Error("admin: retire oauth signing key", "kid", kid, "error", err)
		http.Redirect(w, r, "/admin/signing-keys?flash=error", http.StatusFound)
	}
}

// PostDeleteSigningKey removes a retired key permanently.
func (h *Handler) PostDeleteSigningKey(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	if kid == "" {
		http.Redirect(w, r, "/admin/signing-keys?flash=error", http.StatusFound)
		return
	}

	err := h.signingKeys.DeleteSigningKey(r.Context(), kid)
	switch {
	case err == nil:
		h.logAudit(r, AuditActionOAuthKeyDelete, "oauth_signing_key", kid, "")
		http.Redirect(w, r, "/admin/signing-keys?flash=key-deleted", http.StatusFound)
	case errors.Is(err, oauth.ErrSigningKeyActive):
		h.renderSigningKeys(w, r, h.baseFlash(r, "signing-keys", &Flash{
			Type:    "error",
			Message: "Only a retired key can be deleted. Retire it first.",
		}))
	case errors.Is(err, oauth.ErrSigningKeyNotFound):
		http.Redirect(w, r, "/admin/signing-keys?flash=error", http.StatusFound)
	default:
		h.logger.Error("admin: delete oauth signing key", "kid", kid, "error", err)
		http.Redirect(w, r, "/admin/signing-keys?flash=error", http.StatusFound)
	}
}

// renderSigningKeys loads the key history and renders the page. A listing
// failure is fatal: the page exists to show the keys, and a partial list would
// misrepresent which key is current.
func (h *Handler) renderSigningKeys(w http.ResponseWriter, r *http.Request, base basePage) {
	keys, err := h.signingKeys.ListSigningKeys(r.Context())
	if err != nil {
		h.logger.Error("admin: list oauth signing keys", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// ListSigningKeys is newest first, matching the signing order: the first
	// non-retired key is the current one.
	rows := make([]signingKeyRow, 0, len(keys))
	active := 0
	for _, key := range keys {
		if !key.Retired() {
			active++
		}
	}
	currentAssigned := false
	for _, key := range keys {
		row := signingKeyRow{
			KID:       key.KID,
			CreatedAt: key.CreatedAt,
			RetiredAt: key.RetiredAt,
		}
		if !key.Retired() && !currentAssigned {
			row.Current = true
			currentAssigned = true
		}
		row.CanRetire = !key.Retired() && active > 1
		rows = append(rows, row)
	}

	data := signingKeysData{basePage: base, Keys: rows}
	h.render(w, r, "admin-signing-keys", data)
}
