package authlog

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// timeLayout is how CreatedAt is persisted and compared. A fixed-width UTC
// format keeps SQLite's lexicographic ordering identical to chronological
// ordering; RFC3339Nano's trimmed trailing zeros would not (for example,
// ".5" sorts before "Z" within the same second).
const timeLayout = "2006-01-02 15:04:05.000000000"

const (
	// defaultListLimit applies when Filter.Limit is not positive.
	defaultListLimit = 100
	// maxListLimit caps a caller-supplied page size.
	maxListLimit = 500
)

// Filter constrains a List or Count query. Zero values mean "no constraint".
type Filter struct {
	// Event matches one of the exported event names exactly.
	Event string
	// Outcome matches one of the exported outcomes exactly.
	Outcome string
	// Username matches a case-insensitive substring of the recorded username.
	Username string
	// Since includes only events created at or after this time when non-zero.
	Since time.Time
	// Limit is the page size. Zero or negative uses defaultListLimit.
	Limit int
	// Offset is the number of rows to skip. Negative is treated as zero.
	Offset int
}

// Store persists authentication events in SQLite.
type Store struct {
	db *sql.DB
}

// NewStore creates a Store backed by the given database.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Append inserts an event. A missing ID or CreatedAt is filled in here so a
// caller writing directly to the store still produces a well-formed row; the
// Recorder fills both before calling.
func (s *Store) Append(ctx context.Context, e *Event) error {
	if e == nil {
		return errors.New("authlog: append nil event")
	}
	if e.ID == "" {
		id, err := newID()
		if err != nil {
			return fmt.Errorf("authlog append: %w", err)
		}
		e.ID = id
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	const query = `
		INSERT INTO auth_events
			(id, event, outcome, user_id, username, ip_address, user_agent, detail, created_at)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if _, err := s.db.ExecContext(ctx, query,
		e.ID, e.Event, e.Outcome, e.UserID, e.Username,
		e.IP, e.UserAgent, e.Detail, e.CreatedAt.UTC().Format(timeLayout),
	); err != nil {
		return fmt.Errorf("authlog store append: %w", err)
	}
	return nil
}

// List returns events matching f, newest first. Ordering falls back to the ID
// so events recorded within the same captured timestamp still page stably.
func (s *Store) List(ctx context.Context, f Filter) ([]*Event, error) {
	where, args := f.predicate()

	query := `
		SELECT id, event, outcome, user_id, username, ip_address, user_agent, detail, created_at
		FROM auth_events` + where + `
		ORDER BY created_at DESC, id DESC
		LIMIT ? OFFSET ?`
	args = append(args, f.limit(), f.offset())

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("authlog store list: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e := &Event{}
		if err := rows.Scan(
			&e.ID, &e.Event, &e.Outcome, &e.UserID, &e.Username,
			&e.IP, &e.UserAgent, &e.Detail, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("authlog store list scan: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authlog store list rows: %w", err)
	}
	return events, nil
}

// Count returns the number of events matching f, ignoring Limit and Offset.
func (s *Store) Count(ctx context.Context, f Filter) (int, error) {
	where, args := f.predicate()

	query := "SELECT COUNT(*) FROM auth_events" + where

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("authlog store count: %w", err)
	}
	return count, nil
}

// PurgeBefore deletes events created before cutoff and reports how many rows
// were removed.
func (s *Store) PurgeBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	const query = "DELETE FROM auth_events WHERE created_at < ?"

	res, err := s.db.ExecContext(ctx, query, cutoff.UTC().Format(timeLayout))
	if err != nil {
		return 0, fmt.Errorf("authlog store purge: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("authlog store purge rows affected: %w", err)
	}
	return n, nil
}

// predicate builds the shared WHERE clause for List and Count. Every value is
// bound as a query parameter; user input never reaches the SQL text.
func (f Filter) predicate() (string, []any) {
	conds := make([]string, 0, 4)
	args := make([]any, 0, 4)

	if f.Event != "" {
		conds = append(conds, "event = ?")
		args = append(args, f.Event)
	}
	if f.Outcome != "" {
		conds = append(conds, "outcome = ?")
		args = append(args, f.Outcome)
	}
	if f.Username != "" {
		conds = append(conds, `username LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(f.Username)+"%")
	}
	if !f.Since.IsZero() {
		conds = append(conds, "created_at >= ?")
		args = append(args, f.Since.UTC().Format(timeLayout))
	}

	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func (f Filter) limit() int {
	switch {
	case f.Limit <= 0:
		return defaultListLimit
	case f.Limit > maxListLimit:
		return maxListLimit
	default:
		return f.Limit
	}
}

func (f Filter) offset() int {
	if f.Offset < 0 {
		return 0
	}
	return f.Offset
}

// escapeLike neutralises the LIKE wildcards in user input so a username filter
// of "100%" searches for the literal text rather than matching everything.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// newID returns 16 crypto/rand bytes as hex — 128 bits of entropy, ample for a
// non-secret primary key and generated without locking or coordination.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate auth event id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
