package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrSettingNotFound is returned when a settings key does not exist.
var ErrSettingNotFound = errors.New("admin: setting not found")

// SettingsStore is the persistence interface for site-wide settings.
// It is defined here at the consumer boundary.
type SettingsStore interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
	GetAll(ctx context.Context) (map[string]string, error)
}

// SQLiteSettingsStore implements SettingsStore using a SQLite database.
type SQLiteSettingsStore struct {
	db *sql.DB
}

// NewSQLiteSettingsStore creates a new SQLiteSettingsStore backed by the given database.
func NewSQLiteSettingsStore(db *sql.DB) *SQLiteSettingsStore {
	return &SQLiteSettingsStore{db: db}
}

// Get retrieves the value for the given settings key.
// Returns ErrSettingNotFound if the key does not exist.
func (s *SQLiteSettingsStore) Get(ctx context.Context, key string) (string, error) {
	const query = `SELECT value FROM settings WHERE key = ?`
	var value string
	err := s.db.QueryRowContext(ctx, query, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrSettingNotFound
		}
		return "", fmt.Errorf("settings store get %q: %w", key, err)
	}
	return value, nil
}

// Set stores a value for the given settings key using INSERT OR REPLACE.
func (s *SQLiteSettingsStore) Set(ctx context.Context, key, value string) error {
	const query = `
		INSERT OR REPLACE INTO settings (key, value, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)`
	if _, err := s.db.ExecContext(ctx, query, key, value); err != nil {
		return fmt.Errorf("settings store set %q: %w", key, err)
	}
	return nil
}

// GetAll returns all settings as a key-value map.
func (s *SQLiteSettingsStore) GetAll(ctx context.Context) (map[string]string, error) {
	const query = `SELECT key, value FROM settings ORDER BY key`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("settings store get all: %w", err)
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("settings store get all scan: %w", err)
		}
		result[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("settings store get all rows: %w", err)
	}
	return result, nil
}
