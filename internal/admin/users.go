package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/user"
)

type usersData struct {
	basePage
	Users  []*user.User
	Pager  pagination
	locked map[string]bool // lower-cased username -> currently locked
	// mfaEnabled is user ID -> has a completed TOTP enrollment. Keyed by ID
	// because usernames are user-editable and IDs are not.
	mfaEnabled map[string]bool
}

// IsLocked reports whether username has an active login lock. Templates cannot
// lower-case, so the lookup normalises here.
func (d usersData) IsLocked(username string) bool {
	return d.locked[strings.ToLower(strings.TrimSpace(username))]
}

// MFAEnabled reports whether the user has two-factor authentication enabled.
func (d usersData) MFAEnabled(userID string) bool {
	return d.mfaEnabled[userID]
}

// GetUsers renders the user list page.
func (h *Handler) GetUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := h.userStore.List(ctx)
	if err != nil {
		h.logger.Error("admin: list users", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// One query for the whole page, not one per row. A throttle failure must
	// not take down the user list: render it without badges and log.
	locked := make(map[string]bool)
	if h.throttle != nil {
		states, err := h.throttle.ListLocked(ctx)
		if err != nil {
			h.logger.Warn("admin: list locked accounts", "error", err)
		} else {
			for _, state := range states {
				locked[strings.ToLower(state.Username)] = true
			}
		}
	}

	// One query for the whole page. A failure here must not hide the user
	// list: render without MFA badges and log.
	mfaEnabled := make(map[string]bool)
	if h.mfa != nil {
		ids, err := h.mfa.ListEnabledIDs(ctx)
		if err != nil {
			h.logger.Warn("admin: list users with MFA", "error", err)
		} else {
			for _, id := range ids {
				mfaEnabled[id] = true
			}
		}
	}

	pager := h.paginationFor(w, r, r.URL.Query(), "/admin/users", "page", "per_page", len(users), pageSizeUsers)
	h.render(w, r, "admin-users", usersData{
		basePage:   h.baseQueryFlash(r, "users"),
		Users:      pageItems(users, pager),
		Pager:      pager,
		locked:     locked,
		mfaEnabled: mfaEnabled,
	})
}

type userFormData struct {
	basePage
	EditUser     *user.User
	IsNew        bool
	PasskeyCount int
}

// GetNewUser renders the new user form.
func (h *Handler) GetNewUser(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin-user-form", userFormData{
		basePage: h.base(r, "users"),
		IsNew:    true,
	})
}

// PostCreateUser handles admin user creation, bypassing allow_registration.
func (h *Handler) PostCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: "Invalid form submission."}),
			IsNew:    true,
		})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	emailAddr := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	password := r.FormValue("password")
	isAdmin := r.FormValue("is_admin") == "on"
	isActive := r.FormValue("is_active") == "on"

	draft := &user.User{
		Username: username,
		Email:    emailAddr,
		Name:     name,
		IsAdmin:  isAdmin,
		IsActive: isActive,
		Roles:    "[]",
	}

	if username == "" || emailAddr == "" || len(password) < 8 {
		msg := "Username, email and password (min 8 chars) are required."
		if len(password) > 0 && len(password) < 8 {
			msg = "Password must be at least 8 characters."
		}
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			EditUser: draft,
			IsNew:    true,
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), settings.Int(r.Context(), h.settings, settings.BcryptCost, h.cfg.Auth.BcryptCost, 10, 31))
	if err != nil {
		msg := "Internal error. Please try again."
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			msg = "Password must be at most 72 bytes."
		} else {
			h.logger.Error("admin: hash password", "error", err)
		}
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			EditUser: draft,
			IsNew:    true,
		})
		return
	}

	u := &user.User{
		Username:     username,
		Email:        strings.ToLower(emailAddr),
		Name:         name,
		PasswordHash: string(hash),
		IsAdmin:      isAdmin,
		IsActive:     isActive,
		Roles:        "[]",
	}

	if err := h.userStore.Create(r.Context(), u); err != nil {
		msg := "Failed to create user."
		if errors.Is(err, user.ErrUsernameTaken) {
			msg = "That username is already taken."
		} else if errors.Is(err, user.ErrEmailTaken) {
			msg = "An account with that email already exists."
		}
		h.render(w, r, "admin-user-form", userFormData{
			basePage: h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			EditUser: draft,
			IsNew:    true,
		})
		return
	}

	h.logAudit(r, AuditActionUserCreate, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=created", http.StatusFound)
}

// GetEditUser renders the edit user form.
func (h *Handler) GetEditUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for edit", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	passkeyCount, err := h.credentials.CountByUser(r.Context(), id)
	if err != nil {
		// Non-fatal: log and continue with zero count.
		h.logger.Warn("admin: count passkeys for user", "id", id, "error", err)
	}

	h.render(w, r, "admin-user-form", userFormData{
		basePage:     h.baseQueryFlash(r, "users"),
		EditUser:     u,
		IsNew:        false,
		PasskeyCount: passkeyCount,
	})
}

// PostUpdateUser handles saving changes to an existing user.
func (h *Handler) PostUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s", id), http.StatusFound)
		return
	}

	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for update", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	passkeyCount := 0
	renderErr := func(msg string) {
		if h.credentials != nil {
			if c, cerr := h.credentials.CountByUser(r.Context(), id); cerr == nil {
				passkeyCount = c
			}
		}
		h.render(w, r, "admin-user-form", userFormData{
			basePage:     h.baseFlash(r, "users", &Flash{Type: "error", Message: msg}),
			EditUser:     u,
			IsNew:        false,
			PasskeyCount: passkeyCount,
		})
	}

	u.Username = strings.TrimSpace(r.FormValue("username"))
	u.Email = strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	u.Name = strings.TrimSpace(r.FormValue("name"))
	u.IsAdmin = r.FormValue("is_admin") == "on"
	u.IsActive = r.FormValue("is_active") == "on"

	if u.Username == "" || u.Email == "" {
		renderErr("Username and email are required.")
		return
	}

	// Prevent self-lockout: an administrator cannot strip their own admin role
	// or deactivate their own account.
	if actingUser, ok := session.UserFromContext(r.Context()); ok && actingUser != nil && actingUser.ID == id {
		if !u.IsAdmin || !u.IsActive {
			renderErr("You cannot remove your own administrator role or deactivate your own account.")
			return
		}
	}

	if err := h.userStore.Update(r.Context(), u); err != nil {
		msg := "Failed to update user."
		if errors.Is(err, user.ErrUsernameTaken) {
			msg = "That username is already taken."
		} else if errors.Is(err, user.ErrEmailTaken) {
			msg = "An account with that email already exists."
		}
		renderErr(msg)
		return
	}

	// If the user was deactivated, revoke all their active sessions immediately.
	if !u.IsActive {
		if err := h.sessions.RevokeAllByUser(r.Context(), u.ID); err != nil {
			h.logger.Warn("admin: revoke sessions for deactivated user", "user_id", u.ID, "error", err)
		}
	}

	h.logAudit(r, AuditActionUserUpdate, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=updated", http.StatusFound)
}

// PostDeleteUser deletes a user by ID.
// An admin cannot delete their own account to prevent self-lockout.
func (h *Handler) PostDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Guard: prevent an admin from deleting their own account.
	if actingUser, ok := session.UserFromContext(r.Context()); ok && actingUser.ID == id {
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s?flash=self-delete-forbidden", id), http.StatusFound)
		return
	}

	// Fetch the user before deletion to capture the username for the audit log.
	target, fetchErr := h.userStore.GetByID(r.Context(), id)

	if err := h.userStore.Delete(r.Context(), id); err != nil && !errors.Is(err, user.ErrNotFound) {
		h.logger.Error("admin: delete user", "id", id, "error", err)
		flash := "error"
		if strings.Contains(strings.ToUpper(err.Error()), "FOREIGN KEY") {
			flash = "delete-has-audit"
		}
		http.Redirect(w, r, "/admin/users?flash="+flash, http.StatusFound)
		return
	}

	username := id
	if fetchErr == nil && target != nil {
		username = target.Username
	}
	h.logAudit(r, AuditActionUserDelete, "user", id, username)
	http.Redirect(w, r, "/admin/users?flash=deleted", http.StatusFound)
}

// PostResetUserPassword generates a password reset token and sends the email.
func (h *Handler) PostResetUserPassword(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for password reset", "id", id, "error", err)
		http.Redirect(w, r, "/admin/users?flash=error", http.StatusFound)
		return
	}

	token, err := h.userSvc.GeneratePasswordReset(r.Context(), u.Email)
	if err != nil {
		h.logger.Error("admin: generate password reset", "id", id, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s?flash=error", id), http.StatusFound)
		return
	}

	if token != "" {
		resetURL := h.publicBaseURL(r) + "/reset/" + token
		if err := h.mailer.SendPasswordReset(r.Context(), u.Email, u.Name, resetURL); err != nil {
			h.logger.Warn("admin: send password reset email", "error", err, "user_id", id)
			http.Redirect(w, r, fmt.Sprintf("/admin/users/%s?flash=error", id), http.StatusFound)
			return
		}
	}

	h.logAudit(r, AuditActionUserPasswordReset, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=reset-sent", http.StatusFound)
}

// PostUnlockUser clears a per-account login lock and records an audit entry.
// The lock is temporary on its own; this is the operator's "let them back in
// now" action.
func (h *Handler) PostUnlockUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for unlock", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if h.throttle != nil {
		if err := h.throttle.Unlock(r.Context(), u.Username); err != nil {
			h.logger.Error("admin: unlock user", "user_id", id, "error", err)
			http.Redirect(w, r, "/admin/users?flash=error", http.StatusFound)
			return
		}
	}

	h.logAudit(r, AuditActionUserUnlock, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=unlocked", http.StatusFound)
}

// PostResetMFA removes a user's two-factor authentication and recovery codes so
// a second admin can recover an account whose device is lost. It is the
// supported alternative to deleting rows from SQLite by hand.
//
// Deliberately not self-service: a signed-in user disables their own MFA from
// the Security page, with the current password.
func (h *Handler) PostResetMFA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	u, err := h.userStore.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			http.Redirect(w, r, "/admin/users", http.StatusFound)
			return
		}
		h.logger.Error("admin: get user for MFA reset", "id", id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if h.mfa != nil {
		if err := h.mfa.Reset(r.Context(), u.ID); err != nil {
			h.logger.Error("admin: reset MFA", "user_id", u.ID, "error", err)
			http.Redirect(w, r, "/admin/users?flash=error", http.StatusFound)
			return
		}
	}

	if h.authRecorder != nil {
		h.authRecorder.Record(r.Context(), authlog.Event{
			Event:     authlog.EventMFAReset,
			Outcome:   authlog.OutcomeSuccess,
			UserID:    u.ID,
			Username:  u.Username,
			IP:        authlog.ClientIP(r),
			UserAgent: r.UserAgent(),
			Detail:    "admin reset",
		})
	}

	h.logAudit(r, AuditActionUserMFAReset, "user", u.ID, u.Username)
	http.Redirect(w, r, "/admin/users?flash=mfa-reset", http.StatusFound)
}

// PostRevokeAllUserSessions revokes all active sessions for a user.
// This is a non-destructive operation — the user account is not modified.
func (h *Handler) PostRevokeAllUserSessions(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.sessions.RevokeAllByUser(r.Context(), id); err != nil {
		h.logger.Error("admin: revoke all sessions for user", "user_id", id, "error", err)
		http.Redirect(w, r, fmt.Sprintf("/admin/users/%s?flash=error", id), http.StatusFound)
		return
	}

	// Best-effort fetch for audit target_name.
	username := id
	if u, err := h.userStore.GetByID(r.Context(), id); err == nil {
		username = u.Username
	}
	h.logAudit(r, AuditActionSessionRevokeAll, "user", id, username)
	http.Redirect(w, r, fmt.Sprintf("/admin/users/%s?flash=sessions-revoked", id), http.StatusFound)
}
