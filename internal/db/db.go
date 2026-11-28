package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/pressly/goose/v3"
	"modernc.org/sqlite" // SQLite driver (pure Go, no CGo). Named import also registers the driver.
)

//go:embed migrations/*.sql
var migrations embed.FS

// buildDSN attaches connection-level pragmas to the SQLite DSN so every
// connection opened by database/sql (including reconnects after transient
// errors) automatically enforces foreign keys, busy_timeout, and WAL mode.
func buildDSN(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return path + sep + "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}
	return path + sep + "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
}

// Open opens the SQLite database at path, enables WAL mode and foreign keys,
// and runs all pending goose migrations.
//
// Pass ":memory:" as path for an in-memory database (useful in tests).
func Open(ctx context.Context, path string, logger *slog.Logger) (*sql.DB, error) {
	database, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %q: %w", path, err)
	}

	// SQLite with WAL mode allows concurrent reads but serialises writes.
	// A single writer connection avoids SQLITE_BUSY errors under concurrent load.
	database.SetMaxOpenConns(1)

	// Verify the connection is usable.
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		// SQLite error code 14 (SQLITE_CANTOPEN) surfaces with the misleading
		// message "out of memory". Detect it explicitly and report the real cause.
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == 14 {
			return nil, fmt.Errorf("cannot open database file %q: check that the directory exists and the process has read/write permission: %w", path, err)
		}
		return nil, fmt.Errorf("ping database: %w", err)
	}

	// Create a sub-FS rooted at "migrations/" so goose sees the SQL files at the root.
	migrationsFS, err := fs.Sub(migrations, "migrations")
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("create migrations sub-fs: %w", err)
	}

	// Run goose migrations using the non-global Provider API, which avoids
	// mutating any global state and is safe for concurrent test use.
	provider, err := goose.NewProvider(
		goose.DialectSQLite3,
		database,
		migrationsFS,
		goose.WithSlog(logger),
		// Parallel feature branches can merge migration files out of numeric
		// order (e.g. 017 lands before 016). Without this, a database that has
		// already recorded the higher version refuses to start when the lower
		// one appears — an auth outage caused by bookkeeping, not by schema.
		// Safe here because every migration in this project is additive and
		// independent: see the migration rules in AGENTS.md.
		goose.WithAllowOutofOrder(true),
	)
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("create migration provider: %w", err)
	}

	if _, err := provider.Up(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return database, nil
}
