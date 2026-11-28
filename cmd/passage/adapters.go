package main

import (
	"context"
	"fmt"
	"time"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/adminapi"
	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/idp"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/user"
)

// magicLinkThrottleConfig maps the admin "Magic link" rate limit onto the
// failed-guess throttle: N failed guesses per the configured window, then a
// magicLinkLockout block. A zero request count disables both.
func magicLinkThrottleConfig(ctx context.Context, store settings.Store, cfg *config.Config) ratelimit.MagicLinkConfig {
	return ratelimit.MagicLinkConfig{
		MaxFailures: settings.Int(ctx, store, settings.RateLimitMagicLinkRequests, cfg.RateLimit.MagicLinkRequests, 0, 100000),
		Window:      time.Duration(settings.Int(ctx, store, settings.RateLimitMagicLinkWindowMinutes, cfg.RateLimit.MagicLinkWindowMinutes, 1, 100000)) * time.Minute,
		Lockout:     magicLinkLockout,
	}
}

// idpButtons adapts the provider store to the login page's button source. It
// lives in the wiring layer because idp imports user, so user cannot import idp.
// Uses ListButtons so rendering GET /login never decrypts provider client secrets.
type idpButtons struct {
	store *idp.ProviderStore
}

func (b idpButtons) ProviderButtons(ctx context.Context) ([]user.ProviderButton, error) {
	buttons, err := b.store.ListButtons(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]user.ProviderButton, len(buttons))
	for i, p := range buttons {
		out[i] = user.ProviderButton{Name: p.Name, Label: p.Label}
	}
	return out, nil
}

// auditAPIAdapter adapts the admin audit service to adminapi.auditSource. The
// admin UI package and the REST API package deliberately do not import each
// other, so the mapping lives here at the wiring layer.
type auditAPIAdapter struct {
	svc *admin.AuditService
}

func (a *auditAPIAdapter) ListAudit(ctx context.Context, limit, offset int) ([]adminapi.AuditRecord, error) {
	events, err := a.svc.List(ctx, admin.AuditFilter{Limit: limit, Offset: offset})
	if err != nil {
		return nil, fmt.Errorf("list audit events for api: %w", err)
	}
	records := make([]adminapi.AuditRecord, len(events))
	for i, e := range events {
		records[i] = adminapi.AuditRecord{
			ID:         e.ID,
			ActorID:    e.ActorID,
			ActorName:  e.ActorName,
			Action:     e.Action,
			TargetType: e.TargetType,
			TargetID:   e.TargetID,
			TargetName: e.TargetName,
			Detail:     e.Detail,
			IPAddress:  e.IPAddress,
			CreatedAt:  e.CreatedAt,
		}
	}
	return records, nil
}

// appDurationAdapter adapts the app store to session.appDurationReader.
// It is unexported and lives at the wiring layer to avoid cross-package coupling.
type appDurationAdapter struct {
	store interface {
		GetByID(ctx context.Context, id string) (*app.App, error)
	}
}

func (a *appDurationAdapter) GetSessionDurationHours(ctx context.Context, appID string) (int, error) {
	ap, err := a.store.GetByID(ctx, appID)
	if err != nil {
		return 0, err
	}
	return ap.SessionDurationHours, nil
}
