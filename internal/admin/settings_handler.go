package admin

import (
	"context"
	"net/http"
	"strings"

	"github.com/crueber/passage/internal/settings"
)

// settingsPageData is the template data for the settings page. The page is
// organised into tabs, one section each; a tab is a separate form so saving
// "Email" cannot rewrite "Rate limits".
type settingsPageData struct {
	basePage
	Tabs   []settingsTabLink
	Active settingsSection
}

type settingsTabLink struct {
	ID     string
	Title  string
	Active bool
}

// settingsSectionByID returns the requested section, defaulting to the first.
func settingsSectionByID(sections []settingsSection, id string) settingsSection {
	for _, s := range sections {
		if s.ID == id {
			return s
		}
	}
	return sections[0]
}

func (h *Handler) settingsTabsFor(activeID string) []settingsTabLink {
	out := make([]settingsTabLink, 0, len(settingsTabs))
	for _, t := range settingsTabs {
		out = append(out, settingsTabLink{ID: t.ID, Title: t.Title, Active: t.ID == activeID})
	}
	return out
}

// GetSettings renders the requested settings tab.
func (h *Handler) GetSettings(w http.ResponseWriter, r *http.Request) {
	sec := settingsSectionByID(h.settingsSections(r.Context(), nil), r.URL.Query().Get("tab"))
	h.render(w, r, "admin-settings", settingsPageData{
		basePage: h.baseQueryFlash(r, "settings"),
		Tabs:     h.settingsTabsFor(sec.ID),
		Active:   sec,
	})
}

// PostSettings validates and stores one tab.
func (h *Handler) PostSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/settings", http.StatusFound)
		return
	}
	ctx := r.Context()
	tab := r.FormValue("tab")
	sec := settingsSectionByID(h.settingsSections(ctx, nil), tab)

	values, problems := h.parseSettingsSection(r, sec)
	if len(problems) == 0 {
		problems = h.crossFieldProblems(ctx, sec, values)
	}
	if len(problems) > 0 {
		// Re-render with what was typed and every problem listed, so nothing is
		// lost and the operator does not have to guess.
		h.render(w, r, "admin-settings", settingsPageData{
			basePage: h.baseFlash(r, "settings", &Flash{Type: "error", Message: strings.Join(problems, " ")}),
			Tabs:     h.settingsTabsFor(sec.ID),
			Active:   settingsSectionByID(h.settingsSections(ctx, values), sec.ID),
		})
		return
	}

	var saveErr error
	if bulk, ok := h.settings.(interface {
		SetMany(context.Context, map[string]string) error
	}); ok {
		saveErr = bulk.SetMany(ctx, values)
	} else {
		for key, value := range values {
			if err := h.settings.Set(ctx, key, value); err != nil {
				saveErr = err
				break
			}
		}
	}
	if saveErr != nil {
		h.logger.Error("admin: set settings", "tab", sec.ID, "error", saveErr)
		h.render(w, r, "admin-settings", settingsPageData{
			basePage: h.baseFlash(r, "settings", &Flash{Type: "error", Message: "Failed to save settings. Please try again."}),
			Tabs:     h.settingsTabsFor(sec.ID),
			Active:   settingsSectionByID(h.settingsSections(ctx, values), sec.ID),
		})
		return
	}

	h.logAudit(r, AuditActionSettingsUpdate, "settings", "", sec.ID)
	if h.settingsReload != nil {
		h.settingsReload(ctx)
	}
	http.Redirect(w, r, "/admin/settings?tab="+sec.ID+"&flash=updated", http.StatusFound)
}

// crossFieldProblems enforces rules that span more than one field.
func (h *Handler) crossFieldProblems(ctx context.Context, sec settingsSection, values map[string]string) []string {
	if sec.ID != "auth" {
		return nil
	}
	if values[settings.PasswordEnabled] != "true" &&
		values[settings.PasskeyEnabled] != "true" &&
		values[settings.MagicLinkEnabled] != "true" {
		return []string{"At least one authentication method must stay enabled."}
	}
	if values[settings.MagicLinkEnabled] == "true" {
		// The stored SMTP host is the truth; the config snapshot may be older.
		host := strings.TrimSpace(settings.Raw(ctx, h.settings, settings.SMTPHost, h.cfg.SMTP.Host))
		if host == "" {
			return []string{"Magic link needs an SMTP host; set one under Email first."}
		}
	}
	return nil
}
