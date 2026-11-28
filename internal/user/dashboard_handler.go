package user

import (
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/web"
)

// App view modes. The browser cookie wins over the account default; an empty
// account value means Comfortable.
const (
	appViewComfortable = "comfortable"
	appViewIconized    = "iconized"
	appViewCookieName  = "passage_app_view"
	appViewCookieAge   = 365 * 24 * 60 * 60
)

// dashboardEntry is one rendered app row/tile/command result. The admin console
// is an entry too, but it has no access row to pin and no external URL.
type dashboardEntry struct {
	ID          string
	Name        string
	Description string
	Host        string
	Href        string
	Initial     string
	Search      string
	Favorite    bool
	Admin       bool
	External    bool
	CSRFToken   string
}

// dashboardData is the template data for the "My Apps" page.
type dashboardData struct {
	web.Themed
	User            *User
	AppView         string
	FavoriteEntries []dashboardEntry
	OtherEntries    []dashboardEntry
	AllEntries      []dashboardEntry
	CommandEntries  []dashboardEntry
	SingleApp       bool
	Flash           *Flash
	CSRFToken       string
}

func validAppView(v string) bool {
	return v == appViewComfortable || v == appViewIconized
}

// resolveAppView applies the precedence browser cookie -> account default ->
// Comfortable.
func (h *Handler) resolveAppView(r *http.Request, u *User) string {
	if c, err := r.Cookie(appViewCookieName); err == nil && validAppView(c.Value) {
		return c.Value
	}
	if u != nil && validAppView(u.AppView) {
		return u.AppView
	}
	return appViewComfortable
}

func (h *Handler) setAppViewCookie(w http.ResponseWriter, view string) {
	http.SetCookie(w, &http.Cookie{
		Name:     appViewCookieName,
		Value:    view,
		Path:     "/",
		MaxAge:   appViewCookieAge,
		HttpOnly: false, // the switcher writes this cookie from app.js
		Secure:   h.cfg.Session.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func dashboardInitial(name string) string {
	for _, r := range name {
		return strings.ToUpper(string(r))
	}
	return "?"
}

func dashboardSearch(name, slug, host, description string) string {
	return strings.ToLower(name + " " + slug + " " + host + " " + description)
}

func dashboardEntries(apps []*app.App, favoriteIDs map[string]bool, admin bool, csrfToken string) (favorites, others, all, command []dashboardEntry) {
	entries := make([]dashboardEntry, 0, len(apps)+1)
	if admin {
		entries = append(entries, dashboardEntry{
			ID:          "admin-console",
			Name:        "Passage Admin",
			Description: "Manage users, apps, and settings",
			Host:        "Admin console",
			Href:        "/admin",
			Initial:     "A",
			Search:      dashboardSearch("Passage Admin", "admin", "Admin console", "Manage users apps settings"),
			Admin:       true,
			CSRFToken:   csrfToken,
		})
	}
	for _, a := range apps {
		entries = append(entries, dashboardEntry{
			ID:          a.ID,
			Name:        a.Name,
			Description: a.Description,
			Host:        a.HostPattern,
			Href:        a.DefaultURL,
			Initial:     dashboardInitial(a.Name),
			Search:      dashboardSearch(a.Name, a.Slug, a.HostPattern, a.Description),
			Favorite:    favoriteIDs[a.ID],
			External:    a.DefaultURL != "",
			CSRFToken:   csrfToken,
		})
	}
	all = entries
	for _, e := range entries {
		if e.Admin {
			others = append(others, e)
			continue
		}
		if e.Favorite {
			favorites = append(favorites, e)
		} else {
			others = append(others, e)
		}
	}
	for _, e := range favorites {
		if e.Href != "" {
			command = append(command, e)
		}
	}
	for _, e := range others {
		if e.Href != "" {
			command = append(command, e)
		}
	}
	return favorites, others, all, command
}

// GetDashboard renders the "My Apps" page for the authenticated user.
func (h *Handler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// A no-JS click on the view switch arrives as ?view=...; store it in the
	// browser cookie and return to the clean dashboard URL. A valid cookie wins
	// over the account default on every later visit.
	if view := r.URL.Query().Get("view"); validAppView(view) {
		h.setAppViewCookie(w, view)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	apps, err := h.apps.ListAppsForUser(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("dashboard: list apps for user", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	favorites, err := h.apps.FavoriteIDs(r.Context(), u.ID)
	if err != nil {
		h.logger.Error("dashboard: list favorites", "user_id", u.ID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Pinned apps first, then the name order the store already applied. The sort
	// is stable so pinning does not reshuffle anything else.
	sort.SliceStable(apps, func(i, j int) bool {
		return favorites[apps[i].ID] && !favorites[apps[j].ID]
	})

	csrfToken := csrf.TokenFromContext(r.Context())
	favEntries, otherEntries, allEntries, commandEntries := dashboardEntries(apps, favorites, u.IsAdmin, csrfToken)

	h.render(w, r, "user-dashboard", dashboardData{
		Themed:          web.NewThemed(u.Theme),
		User:            u,
		AppView:         h.resolveAppView(r, u),
		FavoriteEntries: favEntries,
		OtherEntries:    otherEntries,
		AllEntries:      allEntries,
		CommandEntries:  commandEntries,
		SingleApp:       len(apps) == 1 && !u.IsAdmin,
		Flash:           flashFromCode(r.URL.Query().Get("flash")),
		CSRFToken:       csrfToken,
	})
}

// PostToggleFavorite flips the dashboard pin for one app and returns to the
// dashboard. A user who has no access row gets the same redirect and no change:
// the pin belongs to the access grant, so there is nothing to toggle.
func (h *Handler) PostToggleFavorite(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	appID := chi.URLParam(r, "id")
	favorite, found, err := h.apps.ToggleFavorite(r.Context(), u.ID, appID)
	if err != nil {
		h.logger.Error("dashboard: toggle favorite", "user_id", u.ID, "app_id", appID, "error", err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if !found {
		// A stale dashboard (access revoked while the page was open) or a
		// hand-made request. Nothing changed, so this is not worth a warning.
		h.logger.Debug("dashboard: favorite for app without access", "user_id", u.ID, "app_id", appID)
	}
	h.logger.Debug("dashboard: favorite toggled", "user_id", u.ID, "app_id", appID, "favorite", favorite)
	http.Redirect(w, r, "/", http.StatusFound)
}
