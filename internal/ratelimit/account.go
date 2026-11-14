package ratelimit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ErrNotFound is returned by AccountStore.Get when no throttle row exists for
// a username.
var ErrNotFound = errors.New("ratelimit: account not tracked")

// maxAccountKeyBytes bounds a throttle key. Usernames are short in practice;
// the cap stops an unauthenticated request from writing a huge primary key just
// by submitting a huge username on a failed login.
const maxAccountKeyBytes = 128

// accountTimeLayout is how throttle timestamps are persisted and compared. A
// fixed-width UTC format keeps SQLite's lexicographic ordering identical to
// chronological ordering.
const accountTimeLayout = "2006-01-02 15:04:05.000000000"

// AccountConfig controls per-account password-login throttling. A zero value
// for either field disables throttling entirely.
type AccountConfig struct {
	// MaxFailures is the number of consecutive failures that triggers a lock.
	MaxFailures int
	// Lockout is how long an account stays locked once MaxFailures is reached.
	Lockout time.Duration
}

// AccountState is the persisted throttle state for one username.
type AccountState struct {
	Username    string
	Failures    int
	LockedUntil time.Time // zero when the account is not locked
}

// AccountStatus is the effective state at the injected clock's current time.
type AccountStatus struct {
	Locked    bool
	Remaining time.Duration // time until unlock when Locked
	Failures  int           // consecutive failures since the last success or lock
}

// AccountStore persists per-account throttle state in SQLite. Every method
// normalises the username to lower case, so "Admin" and "admin" share one
// bucket — including usernames with no user row.
type AccountStore struct {
	db *sql.DB
}

// NewAccountStore creates an AccountStore backed by the given database.
func NewAccountStore(db *sql.DB) *AccountStore {
	return &AccountStore{db: db}
}

// Get returns the throttle row for username. It returns ErrNotFound when the
// username has never failed a login.
func (s *AccountStore) Get(ctx context.Context, username string) (*AccountState, error) {
	const query = `
		SELECT username, failures, locked_until
		FROM login_throttle
		WHERE username = ?`

	var (
		state  AccountState
		locked sql.NullString
	)
	if err := s.db.QueryRowContext(ctx, query, normalizeUsername(username)).
		Scan(&state.Username, &state.Failures, &locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("account store get: %w", err)
	}

	if locked.Valid && locked.String != "" {
		until, err := parseAccountTime(locked.String)
		if err != nil {
			return nil, fmt.Errorf("account store get: %w", err)
		}
		state.LockedUntil = until
	}
	return &state, nil
}

// RecordFailure atomically inserts or increments the failure counter for
// username and returns the new count. It does not decide whether to lock; the
// Service does that using its configured threshold.
func (s *AccountStore) RecordFailure(ctx context.Context, username string) (int, error) {
	const query = `
		INSERT INTO login_throttle (username, failures, updated_at)
		VALUES (?, 1, CURRENT_TIMESTAMP)
		ON CONFLICT(username) DO UPDATE SET
			failures = failures + 1,
			updated_at = CURRENT_TIMESTAMP
		RETURNING failures`

	var failures int
	if err := s.db.QueryRowContext(ctx, query, normalizeUsername(username)).Scan(&failures); err != nil {
		return 0, fmt.Errorf("account store record failure: %w", err)
	}
	return failures, nil
}

// Lock locks username until the given time and resets its failure counter, so
// the next failure after expiry starts a fresh count.
func (s *AccountStore) Lock(ctx context.Context, username string, until time.Time) error {
	const query = `
		INSERT INTO login_throttle (username, failures, locked_until, updated_at)
		VALUES (?, 0, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(username) DO UPDATE SET
			failures = 0,
			locked_until = excluded.locked_until,
			updated_at = CURRENT_TIMESTAMP`

	if _, err := s.db.ExecContext(ctx, query, normalizeUsername(username), formatAccountTime(until)); err != nil {
		return fmt.Errorf("account store lock: %w", err)
	}
	return nil
}

// Reset clears all throttle state for username. It is called after a
// successful password login.
func (s *AccountStore) Reset(ctx context.Context, username string) error {
	const query = "DELETE FROM login_throttle WHERE username = ?"

	if _, err := s.db.ExecContext(ctx, query, normalizeUsername(username)); err != nil {
		return fmt.Errorf("account store reset: %w", err)
	}
	return nil
}

// Unlock clears all throttle state for username. It is the admin unlock
// action; it is intentionally identical to Reset.
func (s *AccountStore) Unlock(ctx context.Context, username string) error {
	return s.Reset(ctx, username)
}

// ListLocked returns every account whose lock is still in effect at now,
// ordered by soonest unlock first.
func (s *AccountStore) ListLocked(ctx context.Context, now time.Time) ([]*AccountState, error) {
	const query = `
		SELECT username, failures, locked_until
		FROM login_throttle
		WHERE locked_until IS NOT NULL AND locked_until > ?
		ORDER BY locked_until ASC, username ASC`

	rows, err := s.db.QueryContext(ctx, query, formatAccountTime(now))
	if err != nil {
		return nil, fmt.Errorf("account store list locked: %w", err)
	}
	defer rows.Close()

	var states []*AccountState
	for rows.Next() {
		state := &AccountState{}
		var locked sql.NullString
		if err := rows.Scan(&state.Username, &state.Failures, &locked); err != nil {
			return nil, fmt.Errorf("account store list locked scan: %w", err)
		}
		if locked.Valid && locked.String != "" {
			until, err := parseAccountTime(locked.String)
			if err != nil {
				return nil, fmt.Errorf("account store list locked: %w", err)
			}
			state.LockedUntil = until
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("account store list locked rows: %w", err)
	}
	return states, nil
}

// clearExpired removes a lock that has already expired, leaving the row in
// place with a zero failure count. The conditional update avoids racing a
// concurrent lock that was just renewed.
func (s *AccountStore) clearExpired(ctx context.Context, username string, now time.Time) error {
	const query = `
		UPDATE login_throttle
		SET failures = 0, locked_until = NULL, updated_at = CURRENT_TIMESTAMP
		WHERE username = ? AND locked_until IS NOT NULL AND locked_until <= ?`

	if _, err := s.db.ExecContext(ctx, query, normalizeUsername(username), formatAccountTime(now)); err != nil {
		return fmt.Errorf("account store clear expired: %w", err)
	}
	return nil
}

// AccountService applies the lockout policy on top of AccountStore. The clock
// is injected so tests advance time instead of sleeping.
type AccountService struct {
	store *AccountStore
	mu    sync.RWMutex
	cfg   AccountConfig
	now   func() time.Time
}

// NewAccountService creates an AccountService. A nil clock uses time.Now.
func NewAccountService(store *AccountStore, cfg AccountConfig, now func() time.Time) *AccountService {
	if now == nil {
		now = time.Now
	}
	return &AccountService{store: store, cfg: cfg, now: now}
}

// SetConfig changes the lockout policy at runtime. Existing throttle rows stay
// in the database; the next login evaluates them under the new thresholds.
func (s *AccountService) SetConfig(cfg AccountConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == cfg {
		return
	}
	s.cfg = cfg
}

func (s *AccountService) config() AccountConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Enabled reports whether throttling is configured. Either a zero failure
// threshold or a zero lockout duration disables the feature.
func (s *AccountService) Enabled() bool {
	cfg := s.config()
	return cfg.MaxFailures > 0 && cfg.Lockout > 0
}

// Status returns the effective state for username at the current clock time.
// An expired lock is cleared as a side effect of reading it.
func (s *AccountService) Status(ctx context.Context, username string) (AccountStatus, error) {
	if !s.Enabled() {
		return AccountStatus{}, nil
	}

	state, err := s.store.Get(ctx, username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return AccountStatus{}, nil
		}
		return AccountStatus{}, err
	}

	now := s.now()
	if state.LockedUntil.IsZero() {
		return AccountStatus{Failures: state.Failures}, nil
	}
	if state.LockedUntil.After(now) {
		return AccountStatus{
			Locked:    true,
			Remaining: state.LockedUntil.Sub(now),
		}, nil
	}

	// The lock has expired. Clear it before reporting an unlocked state so the
	// next failure starts a fresh count.
	if err := s.store.clearExpired(ctx, username, now); err != nil {
		return AccountStatus{}, err
	}
	return AccountStatus{}, nil
}

// RecordFailure records one invalid password attempt and locks the account
// when the configured threshold is reached. Attempts made while a lock is
// still active are rejected without incrementing the counter.
func (s *AccountService) RecordFailure(ctx context.Context, username string) (AccountStatus, error) {
	if !s.Enabled() {
		return AccountStatus{}, nil
	}

	now := s.now()

	state, err := s.store.Get(ctx, username)
	switch {
	case err == nil && state.LockedUntil.After(now):
		return AccountStatus{Locked: true, Remaining: state.LockedUntil.Sub(now)}, nil
	case err == nil && !state.LockedUntil.IsZero():
		// Expired lock: clear it so this failure starts a fresh count.
		if err := s.store.clearExpired(ctx, username, now); err != nil {
			return AccountStatus{}, err
		}
	case err != nil && !errors.Is(err, ErrNotFound):
		return AccountStatus{}, err
	}

	failures, err := s.store.RecordFailure(ctx, username)
	if err != nil {
		return AccountStatus{}, err
	}

	cfg := s.config()
	if failures >= cfg.MaxFailures {
		until := now.Add(cfg.Lockout)
		if err := s.store.Lock(ctx, username, until); err != nil {
			return AccountStatus{}, err
		}
		return AccountStatus{Locked: true, Remaining: cfg.Lockout}, nil
	}

	return AccountStatus{Failures: failures}, nil
}

// Reset clears the failure counter after a successful password login.
func (s *AccountService) Reset(ctx context.Context, username string) error {
	if !s.Enabled() {
		return nil
	}
	return s.store.Reset(ctx, username)
}

// Unlock clears an account's lock and failure counter. It is the admin unlock
// action, so it works even when throttling has since been disabled.
func (s *AccountService) Unlock(ctx context.Context, username string) error {
	return s.store.Unlock(ctx, username)
}

// ListLocked returns the accounts currently locked at the clock's current
// time, for the admin user list.
func (s *AccountService) ListLocked(ctx context.Context) ([]*AccountState, error) {
	if !s.Enabled() {
		return nil, nil
	}
	return s.store.ListLocked(ctx, s.now())
}

// normalizeUsername is the single definition of a throttle bucket key.
func normalizeUsername(username string) string {
	s := strings.ToLower(strings.TrimSpace(username))
	if len(s) <= maxAccountKeyBytes {
		return s
	}
	cut := maxAccountKeyBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// formatAccountTime renders t in the fixed-width UTC layout used for storage
// and lexicographic comparisons.
func formatAccountTime(t time.Time) string {
	return t.UTC().Format(accountTimeLayout)
}

// parseAccountTime accepts the layout this package writes, plus the formats
// SQLite and database/sql may hand back for a DATETIME value. Only the first
// is expected from our own rows; the rest keep an externally inserted row
// readable instead of turning the login page into a 500.
func parseAccountTime(value string) (time.Time, error) {
	layouts := []string{
		accountTimeLayout,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05.999999999-07:00",
		time.RFC3339Nano,
		time.RFC3339,
	}
	var lastErr error
	for _, layout := range layouts {
		t, err := time.ParseInLocation(layout, value, time.UTC)
		if err == nil {
			return t.UTC(), nil
		}
		lastErr = err
	}
	return time.Time{}, fmt.Errorf("parse throttle time %q: %w", value, lastErr)
}
