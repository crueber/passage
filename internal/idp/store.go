package idp

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors for link operations.
var (
	// ErrLinkNotFound means no (provider, subject) link exists yet.
	ErrLinkNotFound = errors.New("idp: link not found")
	// ErrLinkExists means the (provider, subject) pair is already linked.
	ErrLinkExists = errors.New("idp: link already exists")
)

// Link binds one upstream identity to one local user.
type Link struct {
	ID        string
	UserID    string
	Provider  string
	Subject   string
	Email     string
	CreatedAt time.Time
}

// LinkStore is the persistence interface for upstream identity links. It is
// defined at the consumer boundary, per Go convention.
type LinkStore interface {
	// GetBySubject returns the link for a provider's stable subject.
	GetBySubject(ctx context.Context, provider, subject string) (*Link, error)
	// Create inserts a link. A duplicate (provider, subject) returns
	// ErrLinkExists so a racing callback can re-read instead of failing.
	Create(ctx context.Context, link *Link) error
}

// SQLiteStore implements LinkStore on SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewStore returns a LinkStore backed by db.
func NewStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// newID returns a random UUID v4 string. Links are internal rows; randomness
// only needs to be unique, so crypto/rand is used as everywhere else.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// GetBySubject implements LinkStore.
func (s *SQLiteStore) GetBySubject(ctx context.Context, provider, subject string) (*Link, error) {
	const query = `
		SELECT id, user_id, provider, subject, email, created_at
		FROM idp_links WHERE provider = ? AND subject = ?`
	row := s.db.QueryRowContext(ctx, query, provider, subject)
	l, err := scanLink(row)
	if err != nil {
		return nil, fmt.Errorf("idp store get by subject: %w", err)
	}
	return l, nil
}

// Create implements LinkStore.
func (s *SQLiteStore) Create(ctx context.Context, link *Link) error {
	if link == nil {
		return errors.New("idp store create: nil link")
	}
	id, err := newID()
	if err != nil {
		return fmt.Errorf("idp store create: %w", err)
	}
	link.ID = id
	link.CreatedAt = time.Now().UTC()

	const query = `
		INSERT INTO idp_links (id, user_id, provider, subject, email, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, query,
		link.ID, link.UserID, link.Provider, link.Subject, link.Email, link.CreatedAt,
	); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("idp store create: %w", ErrLinkExists)
		}
		return fmt.Errorf("idp store create: %w", err)
	}
	return nil
}

// scanner is satisfied by *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanLink(s scanner) (*Link, error) {
	var l Link
	if err := s.Scan(&l.ID, &l.UserID, &l.Provider, &l.Subject, &l.Email, &l.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLinkNotFound
		}
		return nil, err
	}
	return &l, nil
}
