package oauth_test

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

// seedAppAndUser inserts a minimal user and app row into the test database and
// returns their IDs. This satisfies foreign key constraints for OAuth records.
func seedAppAndUser(t *testing.T, db *sql.DB) (appID, userID string) {
	t.Helper()

	appID = fmt.Sprintf("app-test-%d", time.Now().UnixNano())
	userID = fmt.Sprintf("user-test-%d", time.Now().UnixNano())

	now := time.Now().UTC()

	_, err := db.Exec(`
		INSERT INTO users (id, username, email, name, is_admin, is_active, roles, created_at, updated_at)
		VALUES (?, ?, ?, ?, 0, 1, '[]', ?, ?)`,
		userID,
		"testuser-"+userID,
		"testuser-"+userID+"@example.com",
		"Test User",
		now, now,
	)
	if err != nil {
		t.Fatalf("seedAppAndUser: insert user: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO apps (id, slug, name, description, host_pattern, is_active,
		                  client_id, client_secret_hash, redirect_uris, oauth_enabled,
		                  created_at, updated_at)
		VALUES (?, ?, ?, '', '', 1, ?, '', '', 1, ?, ?)`,
		appID,
		"test-app-"+appID,
		"Test App",
		"test-client-"+appID,
		now, now,
	)
	if err != nil {
		t.Fatalf("seedAppAndUser: insert app: %v", err)
	}

	return appID, userID
}
