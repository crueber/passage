package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

// ─── Action constants ─────────────────────────────────────────────────────────

const (
	AuditActionUserCreate        = "user.create"
	AuditActionUserUpdate        = "user.update"
	AuditActionUserDelete        = "user.delete"
	AuditActionUserPasswordReset = "user.password_reset"
	AuditActionAppCreate         = "app.create"
	AuditActionAppUpdate         = "app.update"
	AuditActionAppDelete         = "app.delete"
	AuditActionAppGrantAccess    = "app.grant_access"
	AuditActionAppRevokeAccess   = "app.revoke_access"
	AuditActionOAuthGenerate     = "oauth.generate_credentials"
	AuditActionOAuthRotate       = "oauth.rotate_secret"
	AuditActionSessionRevoke     = "session.revoke"
	AuditActionSessionRevokeAll  = "session.revoke_all"
	AuditActionSettingsUpdate    = "settings.update"
	AuditActionAuthMethodUpdate  = "auth.method.update"
)

// ─── Model ────────────────────────────────────────────────────────────────────

// AuditEvent records a single admin action for the audit log.
type AuditEvent struct {
	ID         string
	ActorID    string
	ActorName  string
	Action     string
	TargetType string
	TargetID   string
	TargetName string
	Detail     string
	IPAddress  string
	CreatedAt  time.Time
}

// ─── Store interface ──────────────────────────────────────────────────────────

// AuditFilter constrains an audit log List query.
type AuditFilter struct {
	Action string
	Limit  int
	Offset int
}

// auditStore is the persistence interface for audit log events.
// Defined at the consumer boundary (admin package).
type auditStore interface {
	Create(ctx context.Context, e *AuditEvent) error
	List(ctx context.Context, f AuditFilter) ([]*AuditEvent, error)
}

// ─── SQLite implementation ────────────────────────────────────────────────────

// SQLiteAuditStore implements auditStore using a SQLite database.
type SQLiteAuditStore struct {
	db *sql.DB
}

// NewSQLiteAuditStore creates a new SQLiteAuditStore backed by the given database.
func NewSQLiteAuditStore(db *sql.DB) *SQLiteAuditStore {
	return &SQLiteAuditStore{db: db}
}

// newUUID generates a random UUID v4 using crypto/rand.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	// Set version 4 bits.
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits.
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Create inserts a new audit event into the database.
// The ID is generated here if not already set.
func (s *SQLiteAuditStore) Create(ctx context.Context, e *AuditEvent) error {
	if e.ID == "" {
		id, err := newUUID()
		if err != nil {
			return fmt.Errorf("audit store create: %w", err)
		}
		e.ID = id
	}

	const query = `
		INSERT INTO audit_log
			(id, actor_id, actor_name, action, target_type, target_id, target_name, detail, ip_address)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if _, err := s.db.ExecContext(ctx, query,
		e.ID, e.ActorID, e.ActorName, e.Action,
		e.TargetType, e.TargetID, e.TargetName,
		e.Detail, e.IPAddress,
	); err != nil {
		return fmt.Errorf("audit store create: %w", err)
	}
	return nil
}

// List returns audit events ordered by created_at DESC.
// If f.Action is non-empty, only events with that action are returned.
// f.Limit defaults to 100 when zero; f.Offset provides pagination.
func (s *SQLiteAuditStore) List(ctx context.Context, f AuditFilter) ([]*AuditEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}

	var (
		rows *sql.Rows
		err  error
	)
	if f.Action != "" {
		const q = `
			SELECT id, actor_id, actor_name, action, target_type, target_id, target_name, detail, ip_address, created_at
			FROM audit_log
			WHERE action = ?
			ORDER BY created_at DESC
			LIMIT ? OFFSET ?`
		rows, err = s.db.QueryContext(ctx, q, f.Action, limit, f.Offset)
	} else {
		const q = `
			SELECT id, actor_id, actor_name, action, target_type, target_id, target_name, detail, ip_address, created_at
			FROM audit_log
			ORDER BY created_at DESC
			LIMIT ? OFFSET ?`
		rows, err = s.db.QueryContext(ctx, q, limit, f.Offset)
	}
	if err != nil {
		return nil, fmt.Errorf("audit store list: %w", err)
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		e := &AuditEvent{}
		if err := rows.Scan(
			&e.ID, &e.ActorID, &e.ActorName, &e.Action,
			&e.TargetType, &e.TargetID, &e.TargetName,
			&e.Detail, &e.IPAddress, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("audit store list scan: %w", err)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit store list rows: %w", err)
	}
	return events, nil
}

// ─── Service ──────────────────────────────────────────────────────────────────

// AuditService wraps auditStore with non-fatal logging behaviour.
type AuditService struct {
	store  auditStore
	logger *slog.Logger
}

// NewAuditService creates a new AuditService.
func NewAuditService(store auditStore, logger *slog.Logger) *AuditService {
	return &AuditService{store: store, logger: logger}
}

// Log records an audit event. Errors are logged as warnings and never returned
// so that an audit failure never blocks the primary operation.
func (s *AuditService) Log(ctx context.Context, e *AuditEvent) {
	if err := s.store.Create(ctx, e); err != nil {
		s.logger.Warn("audit: failed to record event",
			"action", e.Action,
			"actor_id", e.ActorID,
			"error", err,
		)
	}
}

// List returns audit events matching the given filter.
func (s *AuditService) List(ctx context.Context, f AuditFilter) ([]*AuditEvent, error) {
	events, err := s.store.List(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("audit service list: %w", err)
	}
	return events, nil
}
