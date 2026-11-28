package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/policy"
)

type appsData struct {
	basePage
	Apps  []*app.App
	Pager pagination
}

// GetApps renders the app list page.
func (h *Handler) GetApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.apps.List(r.Context())
	if err != nil {
		h.logger.Error("admin: list apps", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	pager := h.paginationFor(w, r, r.URL.Query(), "/admin/apps", "page", "per_page", len(apps), pageSizeApps)
	h.render(w, r, "admin-apps", appsData{
		basePage: h.baseQueryFlash(r, "apps"),
		Apps:     pageItems(apps, pager),
		Pager:    pager,
	})
}

// appTabs carries tab-navigation state for app sub-pages (details, OAuth,
// access, groups, roles, policies).
type appTabs struct {
	App       *app.App
	ActiveTab string // "details", "oauth", "access", "groups", "roles" or "policies"
}

type appFormData struct {
	basePage
	appTabs
	EditApp         *app.App
	IsNew           bool
	NewClientSecret string // non-empty only when just generated or rotated; shown once
	BaseURL         string // used to render OIDC endpoint hints in the template
}

// GetNewApp renders the new app form.
func (h *Handler) GetNewApp(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin-app-form", appFormData{
		basePage: h.base(r, "apps"),
		IsNew:    true,
	})
}

// applyAppPolicy copies the nested access-policy inputs from the submitted app
// form onto a. Values are trimmed but not validated here; callers run
// policy.Validate so a malformed rule re-renders the form instead of being
// saved (Evaluate also fails closed if one ever slips through).
func applyAppPolicy(r *http.Request, a *app.App) {
	a.RequiredGroup = strings.TrimSpace(r.FormValue("required_group"))
	a.RequiredRole = strings.TrimSpace(r.FormValue("required_role"))
	a.AllowedCIDRs = strings.TrimSpace(r.FormValue("allowed_cidrs"))
	a.AdminOnly = r.FormValue("admin_only") == "on"
	a.AllowedHours = strings.TrimSpace(r.FormValue("allowed_hours"))
	a.AllowedDays = strings.TrimSpace(r.FormValue("allowed_days"))
}

// formLines splits a one-value-per-line textarea, trimming whitespace and
// dropping blank lines.
func formLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// applyOAuthRegistry copies the app's scope and audience registries from the
// form and validates them. An empty registry means "no restriction", so an app
// that leaves both textareas blank keeps the pre-registry behaviour.
func applyOAuthRegistry(r *http.Request, a *app.App) error {
	a.AllowedScopes = formLines(r.FormValue("scopes"))
	a.AllowedResources = formLines(r.FormValue("resources"))

	var errs []error
	if err := app.ValidateAllowedScopes(a.AllowedScopes); err != nil {
		errs = append(errs, err)
	}
	if err := app.ValidateAllowedResources(a.AllowedResources); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// oauthRegistryFlashMessage turns a joined registry validation error into one
// line for the form's error flash (errors.Join separates with newlines).
func oauthRegistryFlashMessage(err error) string {
	return "OAuth registry: " + strings.ReplaceAll(err.Error(), "\n", "; ")
}

// policyFlashMessage turns a joined policy validation error into one line for
// the form's error flash (errors.Join separates with newlines).
func policyFlashMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), "policy: ")
	return "Access policy: " + strings.ReplaceAll(msg, "\npolicy: ", "; ")
}

// validateAppDetails validates the shared Details-tab fields on an app and
// returns a user-facing validation message, or "" if valid.
func validateAppDetails(a *app.App) string {
	if a.Slug == "" || a.Name == "" {
		return "Slug and name are required."
	}
	if a.DefaultURL != "" {
		u, err := url.Parse(a.DefaultURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "Default URL must start with http:// or https://."
		}
	}
	if err := app.ValidateHostPatternSyntax(a.HostPattern); err != nil {
		return "Host pattern is malformed: " + err.Error()
	}
	for _, rawURI := range a.RedirectURIs {
		u, err := url.Parse(rawURI)
		if err != nil || !u.IsAbs() || u.Fragment != "" || strings.Contains(rawURI, "#") {
			return fmt.Sprintf("Redirect URI %q must be an absolute URI without a fragment.", rawURI)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme == "javascript" || scheme == "data" || scheme == "vbscript" {
			return fmt.Sprintf("Redirect URI %q uses a disallowed scheme.", rawURI)
		}
	}
	return ""
}

// PostCreateApp handles app creation.
func (h *Handler) PostCreateApp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Invalid form submission."}),
			IsNew:    true,
		})
		return
	}

	a := &app.App{
		Slug:        strings.TrimSpace(r.FormValue("slug")),
		Name:        strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")),
		HostPattern: strings.TrimSpace(r.FormValue("host_pattern")),
		DefaultURL:  strings.TrimSpace(r.FormValue("default_url")),
		IsActive:    r.FormValue("is_active") == "on",
	}

	if msg := validateAppDetails(a); msg != "" {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			EditApp:  a,
			IsNew:    true,
		})
		return
	}

	if err := h.apps.Create(r.Context(), a); err != nil {
		msg := "Failed to create app."
		if errors.Is(err, app.ErrSlugTaken) {
			msg = "An app with that slug already exists."
		}
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			EditApp:  a,
			IsNew:    true,
		})
		return
	}

	h.logAudit(r, AuditActionAppCreate, "app", a.ID, a.Name)
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s?flash=created", a.ID), http.StatusFound)
}

// GetEditApp renders the app details tab.
func (h *Handler) GetEditApp(w http.ResponseWriter, r *http.Request) {
	a, ok := h.getAppForAdmin(w, r, "edit")
	if !ok {
		return
	}

	h.render(w, r, "admin-app-form", appFormData{
		basePage: h.baseQueryFlash(r, "apps"),
		appTabs:  appTabs{App: a, ActiveTab: "details"},
		EditApp:  a,
		IsNew:    false,
	})
}

// GetAppOAuth renders the app OAuth tab.
func (h *Handler) GetAppOAuth(w http.ResponseWriter, r *http.Request) {
	a, ok := h.getAppForAdmin(w, r, "oauth tab")
	if !ok {
		return
	}

	h.render(w, r, "admin-app-oauth", appFormData{
		basePage: h.baseQueryFlash(r, "apps"),
		appTabs:  appTabs{App: a, ActiveTab: "oauth"},
		EditApp:  a,
		IsNew:    false,
		BaseURL:  h.baseURL(),
	})
}

// GetAppPolicies renders the optional access-policy tab.
func (h *Handler) GetAppPolicies(w http.ResponseWriter, r *http.Request) {
	a, ok := h.getAppForAdmin(w, r, "policies tab")
	if !ok {
		return
	}

	h.render(w, r, "admin-app-policies", appFormData{
		basePage: h.baseQueryFlash(r, "apps"),
		appTabs:  appTabs{App: a, ActiveTab: "policies"},
		EditApp:  a,
		IsNew:    false,
	})
}

// PostAppPolicies saves only the optional access-policy fields, so saving the
// Details tab can never rewrite a policy (and vice versa).
func (h *Handler) PostAppPolicies(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/policies", id), http.StatusFound)
		return
	}

	a, ok := h.getAppForAdmin(w, r, "policy update")
	if !ok {
		return
	}

	applyAppPolicy(r, a)
	if err := policy.Validate(a.Policy()); err != nil {
		h.render(w, r, "admin-app-policies", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: policyFlashMessage(err)}),
			appTabs:  appTabs{App: a, ActiveTab: "policies"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	if err := h.apps.Update(r.Context(), a); err != nil {
		h.logger.Error("admin: update app policies", "id", id, "error", err)
		h.render(w, r, "admin-app-policies", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: "Failed to save policies."}),
			appTabs:  appTabs{App: a, ActiveTab: "policies"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	h.logAudit(r, AuditActionAppUpdate, "app", a.ID, a.Name)
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/policies?flash=updated", id), http.StatusFound)
}

// parseAppSessionDuration reads the optional per-app OAuth session lifetime.
func parseAppSessionDuration(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.FormValue("session_duration_hours"))
	if raw == "" || raw == "0" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 8760 {
		return 0, errors.New("Session duration must be a whole number between 0 and 8760 (0 = use the global default).")
	}
	return n, nil
}

// PostAppOAuthSettings saves the OAuth-only settings (session lifetime and the
// scope/audience registries) without touching the core Details fields.
func (h *Handler) PostAppOAuthSettings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/oauth", id), http.StatusFound)
		return
	}

	a, ok := h.getAppForAdmin(w, r, "oauth settings")
	if !ok {
		return
	}

	renderErr := func(msg string) {
		h.render(w, r, "admin-app-oauth", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			appTabs:  appTabs{App: a, ActiveTab: "oauth"},
			EditApp:  a,
			IsNew:    false,
			BaseURL:  h.baseURL(),
		})
	}

	if err := applyOAuthRegistry(r, a); err != nil {
		renderErr(oauthRegistryFlashMessage(err))
		return
	}
	duration, err := parseAppSessionDuration(r)
	if err != nil {
		renderErr(err.Error())
		return
	}
	a.SessionDurationHours = duration

	if err := h.apps.Update(r.Context(), a); err != nil {
		h.logger.Error("admin: update app oauth settings", "id", id, "error", err)
		renderErr("Failed to save OAuth settings.")
		return
	}

	h.logAudit(r, AuditActionAppUpdate, "app", a.ID, a.Name)
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s/oauth?flash=updated", id), http.StatusFound)
}

// PostUpdateApp saves changes to an existing app.
func (h *Handler) PostUpdateApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s", id), http.StatusFound)
		return
	}

	a, ok := h.getAppForAdmin(w, r, "update")
	if !ok {
		return
	}

	a.Slug = strings.TrimSpace(r.FormValue("slug"))
	a.Name = strings.TrimSpace(r.FormValue("name"))
	a.Description = strings.TrimSpace(r.FormValue("description"))
	a.HostPattern = strings.TrimSpace(r.FormValue("host_pattern"))
	a.DefaultURL = strings.TrimSpace(r.FormValue("default_url"))
	a.IsActive = r.FormValue("is_active") == "on"
	a.RedirectURIs = formLines(r.FormValue("redirect_uris"))

	if msg := validateAppDetails(a); msg != "" {
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			appTabs:  appTabs{App: a, ActiveTab: "details"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	if err := h.apps.Update(r.Context(), a); err != nil {
		msg := "Failed to update app."
		if errors.Is(err, app.ErrSlugTaken) {
			msg = "An app with that slug already exists."
		}
		h.render(w, r, "admin-app-form", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: msg}),
			appTabs:  appTabs{App: a, ActiveTab: "details"},
			EditApp:  a,
			IsNew:    false,
		})
		return
	}

	h.logAudit(r, AuditActionAppUpdate, "app", a.ID, a.Name)
	http.Redirect(w, r, fmt.Sprintf("/admin/apps/%s?flash=updated", id), http.StatusFound)
}

// PostDeleteApp deletes an app by ID.
func (h *Handler) PostDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Fetch the app before deletion to capture the slug for the audit log.
	target, fetchErr := h.apps.GetByID(r.Context(), id)

	if err := h.apps.Delete(r.Context(), id); err != nil && !errors.Is(err, app.ErrNotFound) {
		h.logger.Error("admin: delete app", "id", id, "error", err)
		http.Redirect(w, r, "/admin/apps?flash=error", http.StatusFound)
		return
	}

	slug := id
	if fetchErr == nil && target != nil {
		slug = target.Slug
	}
	h.logAudit(r, AuditActionAppDelete, "app", id, slug)
	http.Redirect(w, r, "/admin/apps?flash=deleted", http.StatusFound)
}

// PostGenerateOAuthCredentials enables OAuth for an app and generates its
// initial client_id and client_secret. The plaintext secret is shown once in
// the form; it is not stored.
func (h *Handler) PostGenerateOAuthCredentials(w http.ResponseWriter, r *http.Request) {
	h.mutateOAuthCredentials(w, r,
		"oauth generate",
		h.apps.GenerateClientCredentials,
		AuditActionOAuthGenerate,
		"Failed to generate OAuth credentials.",
		"OAuth credentials generated. Copy the secret — it will not be shown again.",
	)
}

// PostRotateOAuthSecret rotates the client secret for an OAuth-enabled app.
// The new plaintext secret is shown once in the form; it is not stored.
func (h *Handler) PostRotateOAuthSecret(w http.ResponseWriter, r *http.Request) {
	h.mutateOAuthCredentials(w, r,
		"oauth rotate",
		h.apps.RotateClientSecret,
		AuditActionOAuthRotate,
		"Failed to rotate OAuth client secret.",
		"OAuth client secret rotated. Copy the new secret — it will not be shown again.",
	)
}

func (h *Handler) mutateOAuthCredentials(
	w http.ResponseWriter,
	r *http.Request,
	purpose string,
	mutate func(ctx context.Context, appID string) (string, error),
	auditAction, failMsg, okMsg string,
) {
	ctx := r.Context()
	a, ok := h.getAppForAdmin(w, r, purpose)
	if !ok {
		return
	}

	secret, err := mutate(ctx, a.ID)
	if err != nil {
		h.render(w, r, "admin-app-oauth", appFormData{
			basePage: h.baseFlash(r, "apps", &Flash{Type: "error", Message: failMsg}),
			appTabs:  appTabs{App: a, ActiveTab: "oauth"},
			EditApp:  a,
			BaseURL:  h.baseURL(),
		})
		return
	}

	if updatedApp, refetchErr := h.apps.GetByID(ctx, a.ID); refetchErr != nil {
		h.logger.Error("admin: re-fetch app after "+purpose, "id", a.ID, "error", refetchErr)
	} else {
		a = updatedApp
	}

	h.logAudit(r, auditAction, "app", a.ID, a.Name)
	h.render(w, r, "admin-app-oauth", appFormData{
		basePage:        h.baseFlash(r, "apps", &Flash{Type: "success", Message: okMsg}),
		appTabs:         appTabs{App: a, ActiveTab: "oauth"},
		EditApp:         a,
		NewClientSecret: secret,
		BaseURL:         h.baseURL(),
	})
}
