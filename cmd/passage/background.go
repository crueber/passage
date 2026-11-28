package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/oauth"
	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/session"
	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/webauthn"
)

// backgroundDeps bundles the components that require periodic housekeeping.
type backgroundDeps struct {
	mfaStore          *mfa.Store
	mfaSvc            *mfa.Service
	sessionStore      *session.SQLiteStore
	sessionSvc        *session.Service
	challenges        *webauthn.SQLiteChallengeStore
	oauthStore        *oauth.SQLiteStore
	authStore         *authlog.Store
	userSvc           *user.Service
	accountThrottle   *ratelimit.AccountService
	magicLinkThrottle *ratelimit.MagicLinkService
	limiters          []*ratelimit.Limiter
}

// startPeriodic runs fn on every interval tick until ctx is cancelled, logging
// any error under name and decrementing wg when the goroutine exits.
func startPeriodic(ctx context.Context, wg *sync.WaitGroup, interval time.Duration, name string, logger *slog.Logger, fn func(context.Context) error) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := fn(ctx); err != nil && ctx.Err() == nil {
					logger.Error(name+" failed", "error", err)
				}
			}
		}
	}()
}

// startBackgroundTasks launches all periodic housekeeping goroutines and the
// one-shot legacy MFA secret re-encryption upgrade. Every goroutine is tracked
// in wg so shutdown can wait for them before closing the SQLite database.
func startBackgroundTasks(ctx context.Context, wg *sync.WaitGroup, d backgroundDeps, logger *slog.Logger) {
	// Rewrite any secret written before encryption existed. Legacy plaintext
	// rows stay readable in the meantime (Decrypt passes them through), so this
	// is a best-effort upgrade off the startup path.
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := d.mfaStore.ReencryptSecrets(ctx)
		if err != nil {
			if ctx.Err() == nil {
				logger.Error("mfa secret re-encryption failed", "error", err)
			}
			return
		}
		if n > 0 {
			logger.Info("encrypted legacy mfa secrets", "count", n)
		}
	}()

	// Hourly session cleanup: absolute expiry plus live idle-timeout sweep so
	// the admin session list does not keep advertising idle-expired sessions.
	startPeriodic(ctx, wg, time.Hour, "session cleanup", logger, func(ctx context.Context) error {
		if err := d.sessionStore.DeleteExpired(ctx); err != nil {
			logger.Error("session cleanup failed", "error", err)
		}
		return d.sessionSvc.DeleteIdleSessions(ctx)
	})

	// WebAuthn and MFA challenges expire quickly; sweep every 10 minutes.
	startPeriodic(ctx, wg, 10*time.Minute, "webauthn challenge cleanup", logger, d.challenges.DeleteExpired)
	startPeriodic(ctx, wg, 10*time.Minute, "mfa challenge cleanup", logger, d.mfaSvc.DeleteExpiredChallenges)

	// Hourly OAuth codes, tokens, and expired revoked-JTI sweep.
	startPeriodic(ctx, wg, time.Hour, "oauth cleanup", logger, d.oauthStore.DeleteExpired)

	// Daily authentication event retention sweep.
	startPeriodic(ctx, wg, 24*time.Hour, "auth event retention", logger, func(ctx context.Context) error {
		_, err := d.authStore.PurgeBefore(ctx, time.Now().UTC().Add(-authLogRetention))
		return err
	})

	// Hourly user token housekeeping: invitations, magic links, password resets,
	// and email verification tokens.
	startPeriodic(ctx, wg, time.Hour, "user token cleanup", logger, func(ctx context.Context) error {
		for _, task := range []struct {
			name string
			fn   func(context.Context) error
		}{
			{"invitation cleanup", d.userSvc.DeleteExpiredInvitations},
			{"magic link token cleanup", d.userSvc.DeleteExpiredMagicLinkTokens},
			{"password reset token cleanup", d.userSvc.DeleteExpiredResetTokens},
			{"email verification token cleanup", d.userSvc.DeleteExpiredEmailVerificationTokens},
		} {
			if err := task.fn(ctx); err != nil && ctx.Err() == nil {
				logger.Error(task.name+" failed", "error", err)
			}
		}
		return nil
	})

	// Hourly SQLite throttle cleanup: stale per-account login_throttle rows and
	// expired magic_link_throttle rows.
	startPeriodic(ctx, wg, time.Hour, "throttle cleanup", logger, func(ctx context.Context) error {
		if _, err := d.accountThrottle.PurgeExpired(ctx, time.Now().UTC().Add(-24*time.Hour)); err != nil && ctx.Err() == nil {
			logger.Error("login throttle cleanup failed", "error", err)
		}
		_, err := d.magicLinkThrottle.PurgeStale(ctx)
		return err
	})

	// Single 5-minute ticker sweeping all in-memory rate-limiter windows.
	startPeriodic(ctx, wg, 5*time.Minute, "rate limiter cleanup", logger, func(context.Context) error {
		for _, l := range d.limiters {
			l.Cleanup()
		}
		return nil
	})
}
