package user

import (
	"errors"
	"net/http"
	"strings"
)

// PostUpdateProfile updates the signed-in user's display name and returns to
// the Security page, where the form lives.
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
		http.Redirect(w, r, "/passkeys?flash=error", http.StatusFound)
		return
	}

	name := strings.TrimSpace(r.FormValue("display_name"))
	if err := h.users.UpdateDisplayName(r.Context(), u.ID, name); err != nil {
		if errors.Is(err, ErrNameTooLong) {
			http.Redirect(w, r, "/passkeys?flash=profile-invalid", http.StatusFound)
			return
		}
		h.logger.Error("profile: update display name", "user_id", u.ID, "error", err)
		http.Redirect(w, r, "/passkeys?flash=error", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/passkeys?flash=profile-saved", http.StatusFound)
}
