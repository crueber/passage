package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // SQLite driver (pure Go, no CGo).
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open opens the SQLite database at path, enables WAL mode and foreign keys,
// and runs all pending goose migrations.
//
// Pass ":memory:" as path for an in-memory database (useful in tests).
func Open(ctx context.Context, path string, logger *slog.Logger) (*sql.DB, error) {
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %q: %w", path, err)
	}

	// SQLite with WAL mode allows concurrent reads but serialises writes.
	// A single writer connection avoids SQLITE_BUSY errors under concurrent load.
	database.SetMaxOpenConns(1)

	// Verify the connection is usable.
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	// Enable WAL journal mode for better read/write concurrency.
	if _, err := database.ExecContext(ctx, "PRAGMA journal_mode=WAL;"); err != nil {
		database.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}

	// Enable foreign key constraint enforcement (disabled by default in SQLite).
	if _, err := database.ExecContext(ctx, "PRAGMA foreign_keys=ON;"); err != nil {
		database.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
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
