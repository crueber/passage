package ratelimit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// maxMagicLinkKeyBytes bounds a throttle key. Client addresses are short; the
// cap stops a spoofed header from writing a huge primary key.
const maxMagicLinkKeyBytes = 128

// MagicLinkConfig controls magic-link request throttling. A zero value for any
// field disables the feature.
type MagicLinkConfig struct {
	// MaxFailures is how many requests for an unknown account lock the address.
	MaxFailures int
	// Window is how long failures are remembered: three failures inside it lock.
	Window time.Duration
	// Lockout is how long an address stays blocked once MaxFailures is reached.
	Lockout time.Duration
}

// MagicLinkState is the persisted throttle state for one client address.
type MagicLinkState struct {
	IP          string
	Failures    int
	WindowStart time.Time // zero when no window is open
	LockedUntil time.Time // zero when the address is not blocked
}

// MagicLinkStatus is the effective state at the injected clock's current time.
type MagicLinkStatus struct {
	Locked    bool
	Remaining time.Duration // time until unblock when Locked
	Failures  int           // failures in the current window
}

// MagicLinkStore persists per-address magic-link failures in SQLite.
type MagicLinkStore struct {
	db *sql.DB
}

// NewMagicLinkStore creates a MagicLinkStore backed by the given database.
func NewMagicLinkStore(db *sql.DB) *MagicLinkStore {
	return &MagicLinkStore{db: db}
}

// Get returns the throttle row for ip, or ErrNotFound when the address has
// never asked for a link to an unknown account.
func (s *MagicLinkStore) Get(ctx context.Context, ip string) (*MagicLinkState, error) {
	const query = `
		SELECT ip, failures, window_started, locked_until
		FROM magic_link_throttle
		WHERE ip = ?`

	var (
		state  MagicLinkState
		window sql.NullString
		locked sql.NullString
	)
	if err := s.db.QueryRowContext(ctx, query, normalizeMagicLinkKey(ip)).
		Scan(&state.IP, &state.Failures, &window, &locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("magic link store get: %w", err)
	}

	if window.Valid && window.String != "" {
		start, err := parseAccountTime(window.String)
		if err != nil {
			return nil, fmt.Errorf("magic link store get: %w", err)
		}
		state.WindowStart = start
	}
	if locked.Valid && locked.String != "" {
		until, err := parseAccountTime(locked.String)
		if err != nil {
			return nil, fmt.Errorf("magic link store get: %w", err)
		}
		state.LockedUntil = until
	}
	return &state, nil
}

// recordFailureRequest carries the values used by the atomic upsert.
type recordFailureRequest struct {
	IP        string
	Now       time.Time
	WindowCut time.Time // failures before this are forgotten
}

// Bump atomically records one failure and returns the count in the current
// window, opening a fresh window when the previous one has expired. Doing the
// rollover and the increment in one statement keeps concurrent requests from
// losing a count.
func (s *MagicLinkStore) Bump(ctx context.Context, req recordFailureRequest) (int, error) {
	const query = `
		INSERT INTO magic_link_throttle (ip, failures, window_started, updated_at)
		VALUES (?, 1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(ip) DO UPDATE SET
			failures = CASE
				WHEN magic_link_throttle.window_started IS NULL
				  OR magic_link_throttle.window_started < ?
				THEN 1
				ELSE magic_link_throttle.failures + 1
			END,
			window_started = CASE
				WHEN magic_link_throttle.window_started IS NULL
				  OR magic_link_throttle.window_started < ?
				THEN excluded.window_started
				ELSE magic_link_throttle.window_started
			END,
			updated_at = CURRENT_TIMESTAMP
		RETURNING failures`

	var failures int
	if err := s.db.QueryRowContext(ctx, query,
		normalizeMagicLinkKey(req.IP),
		formatAccountTime(req.Now),
		formatAccountTime(req.WindowCut),
		formatAccountTime(req.WindowCut),
	).Scan(&failures); err != nil {
		return 0, fmt.Errorf("magic link store bump: %w", err)
	}
	return failures, nil
}

// Lock blocks ip until the given time and clears the failure counter, so the
// next failure after the block expires starts a fresh window.
func (s *MagicLinkStore) Lock(ctx context.Context, ip string, until time.Time) error {
	const query = `
		INSERT INTO magic_link_throttle (ip, failures, locked_until, updated_at)
		VALUES (?, 0, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(ip) DO UPDATE SET
			failures = 0,
			window_started = NULL,
			locked_until = excluded.locked_until,
			updated_at = CURRENT_TIMESTAMP`

	if _, err := s.db.ExecContext(ctx, query, normalizeMagicLinkKey(ip), formatAccountTime(until)); err != nil {
		return fmt.Errorf("magic link store lock: %w", err)
	}
	return nil
}

// clearExpired removes a block that has already ended, leaving the row with no
// failures and no open window.
func (s *MagicLinkStore) clearExpired(ctx context.Context, ip string, now time.Time) error {
	const query = `
		UPDATE magic_link_throttle
		SET failures = 0, window_started = NULL, locked_until = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE ip = ? AND locked_until IS NOT NULL AND locked_until <= ?`

	if _, err := s.db.ExecContext(ctx, query, normalizeMagicLinkKey(ip), formatAccountTime(now)); err != nil {
		return fmt.Errorf("magic link store clear expired: %w", err)
	}
	return nil
}

// PurgeExpired deletes rows that can no longer affect a decision: no active
// block, and either no open window or a window that ended before `before`.
func (s *MagicLinkStore) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	const query = `
		DELETE FROM magic_link_throttle
		WHERE (locked_until IS NULL AND (window_started IS NULL OR window_started < ?))
		   OR (locked_until IS NOT NULL AND locked_until < ?)`

	res, err := s.db.ExecContext(ctx, query, formatAccountTime(before), formatAccountTime(before))
	if err != nil {
		return 0, fmt.Errorf("magic link store purge: %w", err)
	}
	return res.RowsAffected()
}

// MagicLinkService applies the request policy on top of MagicLinkStore. The
// clock is injected so tests advance time instead of sleeping.
type MagicLinkService struct {
	store *MagicLinkStore
	mu    sync.RWMutex
	cfg   MagicLinkConfig
	now   func() time.Time
}

// NewMagicLinkService creates a MagicLinkService. A nil clock uses time.Now.
func NewMagicLinkService(store *MagicLinkStore, cfg MagicLinkConfig, now func() time.Time) *MagicLinkService {
	if now == nil {
		now = time.Now
	}
	return &MagicLinkService{store: store, cfg: cfg, now: now}
}

// SetConfig changes the policy at runtime. Existing rows stay in the database
// and are evaluated under the new thresholds on the next request.
func (s *MagicLinkService) SetConfig(cfg MagicLinkConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
}

func (s *MagicLinkService) config() MagicLinkConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Enabled reports whether throttling is configured. A zero threshold, window or
// lockout disables the feature.
func (s *MagicLinkService) Enabled() bool {
	cfg := s.config()
	return cfg.MaxFailures > 0 && cfg.Window > 0 && cfg.Lockout > 0
}

// Status returns the effective state for ip at the current clock time. A block
// that has ended is cleared as a side effect of reading it.
func (s *MagicLinkService) Status(ctx context.Context, ip string) (MagicLinkStatus, error) {
	if !s.Enabled() {
		return MagicLinkStatus{}, nil
	}

	state, err := s.store.Get(ctx, ip)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return MagicLinkStatus{}, nil
		}
		return MagicLinkStatus{}, err
	}

	now := s.now()
	if state.LockedUntil.IsZero() {
		return MagicLinkStatus{Failures: state.Failures}, nil
	}
	if state.LockedUntil.After(now) {
		return MagicLinkStatus{Locked: true, Remaining: state.LockedUntil.Sub(now)}, nil
	}

	if err := s.store.clearExpired(ctx, ip, now); err != nil {
		return MagicLinkStatus{}, err
	}
	return MagicLinkStatus{}, nil
}

// RecordFailure records one request for an unknown account and blocks the
// address when the threshold is reached inside the window. Requests made while
// a block is active are reported without extending it.
func (s *MagicLinkService) RecordFailure(ctx context.Context, ip string) (MagicLinkStatus, error) {
	if !s.Enabled() {
		return MagicLinkStatus{}, nil
	}

	now := s.now()
	cfg := s.config()

	state, err := s.store.Get(ctx, ip)
	switch {
	case err == nil && state.LockedUntil.After(now):
		return MagicLinkStatus{Locked: true, Remaining: state.LockedUntil.Sub(now)}, nil
	case err == nil && !state.LockedUntil.IsZero():
		// The block has ended: clear it so this failure opens a fresh window.
		if err := s.store.clearExpired(ctx, ip, now); err != nil {
			return MagicLinkStatus{}, err
		}
	case err != nil && !errors.Is(err, ErrNotFound):
		return MagicLinkStatus{}, err
	}

	failures, err := s.store.Bump(ctx, recordFailureRequest{
		IP:        ip,
		Now:       now,
		WindowCut: now.Add(-cfg.Window),
	})
	if err != nil {
		return MagicLinkStatus{}, err
	}

	if failures >= cfg.MaxFailures {
		until := now.Add(cfg.Lockout)
		if err := s.store.Lock(ctx, ip, until); err != nil {
			return MagicLinkStatus{}, err
		}
		return MagicLinkStatus{Locked: true, Remaining: cfg.Lockout}, nil
	}

	return MagicLinkStatus{Failures: failures}, nil
}

// PurgeExpired drops throttle rows that can no longer block or count.
func (s *MagicLinkService) PurgeExpired(ctx context.Context, before time.Time) (int64, error) {
	return s.store.PurgeExpired(ctx, before)
}

// normalizeMagicLinkKey is the single definition of a throttle bucket key.
func normalizeMagicLinkKey(ip string) string {
	s := strings.ToLower(strings.TrimSpace(ip))
	if len(s) > maxMagicLinkKeyBytes {
		return s[:maxMagicLinkKeyBytes]
	}
	return s
}
