package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/idp"
)

// providerManager is the consumer-side view of the upstream provider store.
// Implemented by *idp.ProviderStore and wired in run.go.
type providerManager interface {
	List(ctx context.Context) ([]*idp.Provider, error)
	Get(ctx context.Context, name string) (*idp.Provider, error)
	GetByID(ctx context.Context, id string) (*idp.Provider, error)
	Create(ctx context.Context, p *idp.Provider) error
	Update(ctx context.Context, p *idp.Provider) error
	Delete(ctx context.Context, id string) error
}

// SetProviderManager wires the upstream identity provider store. Call once
// before serving; a nil manager makes the providers page unavailable.
func (h *Handler) SetProviderManager(m providerManager) {
	h.providers = m
}

type providersData struct {
	basePage
	Providers []*idp.Provider
}

type providerFormData struct {
	basePage
	IsNew     bool
	Provider  *idp.Provider
	FormError string
}

// GetProviders lists the configured upstream identity providers.
func (h *Handler) GetProviders(w http.ResponseWriter, r *http.Request) {
	if h.providers == nil {
		http.Error(w, "Identity providers are not available.", http.StatusInternalServerError)
		return
	}
	list, err := h.providers.List(r.Context())
	if err != nil {
		h.logger.Error("admin: list identity providers", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.render(w, r, "admin-providers", providersData{
		basePage:  h.base(r, "providers"),
		Providers: list,
	})
}

// GetNewProvider renders the add form.
func (h *Handler) GetNewProvider(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin-provider-form", providerFormData{
		basePage: h.base(r, "providers"),
		IsNew:    true,
		Provider: &idp.Provider{Scopes: idp.DefaultScopes()},
	})
}

// GetEditProvider renders the edit form for one provider.
func (h *Handler) GetEditProvider(w http.ResponseWriter, r *http.Request) {
	if h.providers == nil {
		http.Error(w, "Identity providers are not available.", http.StatusInternalServerError)
		return
	}
	p, err := h.providers.GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, idp.ErrProviderNotFound) {
			http.NotFound(w, r)
			return
		}
		h.logger.Error("admin: load identity provider", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// Never echo the stored secret back into the form.
	p.ClientSecret = ""
	h.render(w, r, "admin-provider-form", providerFormData{
		basePage: h.base(r, "providers"),
		Provider: p,
	})
}

// PostCreateProvider stores a new provider.
func (h *Handler) PostCreateProvider(w http.ResponseWriter, r *http.Request) {
	p := providerFromForm(r)

	// Uniqueness is checked here so the operator gets the field error rather
	// than a raw constraint violation.
	if existing, err := h.providers.Get(r.Context(), p.Name); err == nil && existing != nil {
		h.renderProviderFormError(w, r, providerFormData{IsNew: true, Provider: p,
			FormError: "That name is already in use by another provider."})
		return
	}
	if err := idp.ValidateProvider(p); err != nil {
		h.renderProviderFormError(w, r, providerFormData{IsNew: true, Provider: p,
			FormError: err.Error()})
		return
	}

	if err := h.providers.Create(r.Context(), p); err != nil {
		h.logger.Error("admin: create identity provider", "error", err)
		h.renderProviderFormError(w, r, providerFormData{IsNew: true, Provider: p,
			FormError: "Failed to save the provider. Please try again."})
		return
	}
	h.logAudit(r, AuditActionProviderCreate, "idp_provider", p.ID, p.Name)
	http.Redirect(w, r, "/admin/providers?flash=created", http.StatusFound)
}

// PostUpdateProvider saves changes to one provider.
func (h *Handler) PostUpdateProvider(w http.ResponseWriter, r *http.Request) {
	existing, err := h.providers.GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, idp.ErrProviderNotFound) {
			http.NotFound(w, r)
			return
		}
		h.logger.Error("admin: load identity provider", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	p := providerFromForm(r)
	p.ID = existing.ID

	if other, err := h.providers.Get(r.Context(), p.Name); err == nil && other != nil && other.ID != p.ID {
		h.renderProviderFormError(w, r, providerFormData{Provider: p,
			FormError: "That name is already in use by another provider."})
		return
	}

	// An empty secret field means "keep the current one"; validate against it
	// but let the store leave the stored ciphertext untouched.
	toValidate := *p
	if toValidate.ClientSecret == "" {
		toValidate.ClientSecret = existing.ClientSecret
	}
	if err := idp.ValidateProvider(&toValidate); err != nil {
		h.renderProviderFormError(w, r, providerFormData{Provider: p, FormError: err.Error()})
		return
	}

	if err := h.providers.Update(r.Context(), p); err != nil {
		h.logger.Error("admin: update identity provider", "error", err)
		h.renderProviderFormError(w, r, providerFormData{Provider: p,
			FormError: "Failed to save the provider. Please try again."})
		return
	}
	h.logAudit(r, AuditActionProviderUpdate, "idp_provider", p.ID, p.Name)
	http.Redirect(w, r, "/admin/providers?flash=updated", http.StatusFound)
}

// PostDeleteProvider removes a provider.
func (h *Handler) PostDeleteProvider(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, err := h.providers.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, idp.ErrProviderNotFound) {
			http.NotFound(w, r)
			return
		}
		h.logger.Error("admin: load identity provider for delete", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := h.providers.Delete(r.Context(), id); err != nil {
		h.logger.Error("admin: delete identity provider", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.logAudit(r, AuditActionProviderDelete, "idp_provider", id, p.Name)
	http.Redirect(w, r, "/admin/providers?flash=deleted", http.StatusFound)
}

func (h *Handler) renderProviderFormError(w http.ResponseWriter, r *http.Request, data providerFormData) {
	data.basePage = h.base(r, "providers")
	h.render(w, r, "admin-provider-form", data)
}

func providerFromForm(r *http.Request) *idp.Provider {
	return &idp.Provider{
		Name:         strings.TrimSpace(r.FormValue("name")),
		Label:        strings.TrimSpace(r.FormValue("label")),
		Issuer:       strings.TrimSpace(r.FormValue("issuer")),
		ClientID:     strings.TrimSpace(r.FormValue("client_id")),
		ClientSecret: r.FormValue("client_secret"),
		Scopes:       formLines(r.FormValue("scopes")),
		AutoCreate:   r.FormValue("auto_create") == "on",
	}
}
