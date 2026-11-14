package user

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/crueber/passage/internal/csrf"
	"github.com/crueber/passage/internal/theme"
	"github.com/crueber/passage/internal/web"
)

// profileData is the render data for the self-service profile page.
type profileData struct {
	web.Themed
	User      *User
	Themes    []theme.Theme
	Flash     *Flash
	CSRFToken string
}

// GetProfile renders the account details page. It is reachable by clicking the
// display name in the top bar, so it needs no separate navigation entry.
func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	var flash *Flash
	switch r.URL.Query().Get("flash") {
	case "saved":
		flash = &Flash{Type: "success", Message: "Profile updated."}
	case "invalid":
		flash = &Flash{Type: "error", Message: fmt.Sprintf("Display name must be at most %d characters.", MaxDisplayNameLength)}
	case "error":
		flash = &Flash{Type: "error", Message: "Could not save your profile. Please try again."}
	}

	h.render(w, r, "profile.html", profileData{
		Themed:    web.Themed{Theme: u.Theme},
		User:      u,
		Themes:    theme.All,
		Flash:     flash,
		CSRFToken: csrf.TokenFromContext(r.Context()),
	})
}

// PostUpdateProfile updates the signed-in user's display name and returns to
// the profile page.
//
// Only the name column is written; username, email and credentials are managed
// elsewhere (an administrator edits them, and the password flows have their
// own forms), so this endpoint cannot become a privilege-escalation surface.
func (h *Handler) PostUpdateProfile(w http.ResponseWriter, r *http.Request) {
	u, ok := h.userCtx(r.Context())
	if !ok || u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/profile?flash=invalid", http.StatusFound)
		return
	}

	name := strings.TrimSpace(r.FormValue("display_name"))
	themeName := strings.TrimSpace(r.FormValue("theme"))
	if len(name) > MaxDisplayNameLength {
		http.Redirect(w, r, "/profile?flash=invalid", http.StatusFound)
		return
	}
	if themeName != "" {
		if _, ok := theme.Lookup(themeName); !ok {
			http.Redirect(w, r, "/profile?flash=invalid", http.StatusFound)
			return
		}
	}

	if err := h.users.UpdateTheme(r.Context(), u.ID, themeName); err != nil {
		if errors.Is(err, ErrInvalidTheme) {
			http.Redirect(w, r, "/profile?flash=invalid", http.StatusFound)
			return
		}
		h.logger.Error("profile: update theme", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/profile?flash=error", http.StatusFound)
		return
	}

	if err := h.users.UpdateDisplayName(r.Context(), u.ID, name); err != nil {
		if errors.Is(err, ErrNameTooLong) {
			http.Redirect(w, r, "/profile?flash=invalid", http.StatusFound)
			return
		}
		h.logger.Error("profile: update display name", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/profile?flash=error", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/profile?flash=saved", http.StatusFound)
}
