package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/adminapi"
)

// apiTokenNameMaxLength bounds a token label. The name is a human reminder of
// where a token is used ("grafana exporter"), not a data field.
const apiTokenNameMaxLength = 100

// apiTokenManager is the admin-facing view of API tokens. Defined at the
// consumer boundary; backed by *adminapi.Service in run.go.
type apiTokenManager interface {
	// Create mints a token and returns its plaintext, which is shown once.
	Create(ctx context.Context, name string) (string, *adminapi.Token, error)
	List(ctx context.Context) ([]*adminapi.Token, error)
	Revoke(ctx context.Context, id string) (*adminapi.Token, error)
}

// apiTokensData is the template data for the API tokens page.
type apiTokensData struct {
	basePage
	Tokens []*adminapi.Token
	// NewToken is the plaintext of a token that was just created. It is the
	// only time it is ever rendered and it is never written to a log.
	NewToken     string
	NewTokenName string
	// Name preserves the submitted label when creation is rejected.
	Name string
}

// GetAPITokens renders the token list and the create form.
func (h *Handler) GetAPITokens(w http.ResponseWriter, r *http.Request) {
	var flash *Flash
	if code := r.URL.Query().Get("flash"); code != "" {
		flash = flashFromQuery(code)
	}
	h.renderAPITokens(w, r, h.baseFlash(r, "api-tokens", flash), apiTokensData{})
}

// PostCreateAPIToken mints a token and renders it exactly once.
func (h *Handler) PostCreateAPIToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderAPITokens(w, r,
			h.baseFlash(r, "api-tokens", &Flash{Type: "error", Message: "Invalid form submission."}),
			apiTokensData{})
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	base := h.baseFlash(r, "api-tokens", nil)
	if name == "" || len(name) > apiTokenNameMaxLength {
		base.Flash = &Flash{Type: "error", Message: "Give the token a name of at most 100 characters."}
		h.renderAPITokens(w, r, base, apiTokensData{Name: name})
		return
	}

	plaintext, token, err := h.apiTokens.Create(r.Context(), name)
	if err != nil {
		if errors.Is(err, adminapi.ErrNameRequired) {
			base.Flash = &Flash{Type: "error", Message: "Give the token a name of at most 100 characters."}
		} else {
			h.logger.Error("admin: create api token", "error", err)
			base.Flash = &Flash{Type: "error", Message: "Failed to create the token. Please try again."}
		}
		h.renderAPITokens(w, r, base, apiTokensData{Name: name})
		return
	}

	// Audit the creation, never the token itself.
	h.logAudit(r, AuditActionAPITokenCreate, "api_token", token.ID, token.Name)

	base.Flash = &Flash{Type: "success", Message: "Token created. Copy it now — it will not be shown again."}
	h.renderAPITokens(w, r, base, apiTokensData{
		NewToken:     plaintext,
		NewTokenName: token.Name,
	})
}

// PostRevokeAPIToken revokes a token. Requests already using it start failing
// with 401 immediately; the row is kept so the history stays readable.
func (h *Handler) PostRevokeAPIToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	token, err := h.apiTokens.Revoke(r.Context(), id)
	if err != nil {
		if errors.Is(err, adminapi.ErrTokenNotFound) {
			http.Redirect(w, r, "/admin/api-tokens?flash=error", http.StatusFound)
			return
		}
		h.logger.Error("admin: revoke api token", "token_id", id, "error", err)
		http.Redirect(w, r, "/admin/api-tokens?flash=error", http.StatusFound)
		return
	}

	h.logAudit(r, AuditActionAPITokenRevoke, "api_token", token.ID, token.Name)
	http.Redirect(w, r, "/admin/api-tokens?flash=api-token-revoked", http.StatusFound)
}

// renderAPITokens loads the token list and renders the page. A listing failure
// is fatal here: the page exists to show the tokens, and a half-rendered list
// would be misleading.
func (h *Handler) renderAPITokens(w http.ResponseWriter, r *http.Request, base basePage, data apiTokensData) {
	tokens, err := h.apiTokens.List(r.Context())
	if err != nil {
		h.logger.Error("admin: list api tokens", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data.basePage = base
	data.Tokens = tokens
	h.render(w, r, "admin-api-tokens", data)
}
