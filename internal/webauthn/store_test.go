package webauthn_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/webauthn"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// insertUser inserts a minimal user row so FK constraints are satisfied.
func insertUser(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (id, username, email, name, password_hash, is_admin, is_active, roles, created_at, updated_at)
		 VALUES (?, ?, ?, '', '', 0, 1, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		id, id+"_username", id+"@example.com",
	)
	if err != nil {
		t.Fatalf("insertUser %q: %v", id, err)
	}
}

// makeTestCredential returns a minimal Credential ready for insertion.
// The PublicKey is a JSON-marshalled gowebauthn.Credential stub.
func makeTestCredential(t *testing.T, id, userID string) *webauthn.Credential {
	t.Helper()
	stub := gowebauthn.Credential{
		ID:        []byte(id),
		PublicKey: []byte("fake-public-key"),
	}
	pubKeyJSON, err := json.Marshal(stub)
	if err != nil {
		t.Fatalf("marshal credential stub: %v", err)
	}
	return &webauthn.Credential{
		ID:        id,
		UserID:    userID,
		Name:      "Test passkey",
		PublicKey: pubKeyJSON,
		SignCount: 0,
	}
}

// ─── SQLiteCredentialStore tests ─────────────────────────────────────────────

func TestCredentialStore_CreateAndGetByID(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteCredentialStore(database)
	ctx := context.Background()

	insertUser(t, database, "user-abc")
	cred := makeTestCredential(t, "cred-001", "user-abc")

	if err := store.Create(ctx, cred); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.GetByID(ctx, "cred-001")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	if got.ID != cred.ID {
		t.Errorf("ID: got %q, want %q", got.ID, cred.ID)
	}
	if got.UserID != cred.UserID {
		t.Errorf("UserID: got %q, want %q", got.UserID, cred.UserID)
	}
	if got.Name != cred.Name {
		t.Errorf("Name: got %q, want %q", got.Name, cred.Name)
	}
	if got.LastUsedAt != nil {
		t.Errorf("LastUsedAt: expected nil, got %v", got.LastUsedAt)
	}
}

func TestCredentialStore_GetByID_NotFound(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteCredentialStore(database)
	ctx := context.Background()

	_, err := store.GetByID(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCredentialStore_ListByUser(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteCredentialStore(database)
	ctx := context.Background()

	insertUser(t, database, "user-abc")
	insertUser(t, database, "user-xyz")
	cred1 := makeTestCredential(t, "cred-001", "user-abc")
	cred2 := makeTestCredential(t, "cred-002", "user-abc")
	cred3 := makeTestCredential(t, "cred-003", "user-xyz") // different user

	for _, c := range []*webauthn.Credential{cred1, cred2, cred3} {
		if err := store.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	creds, err := store.ListByUser(ctx, "user-abc")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(creds) != 2 {
		t.Errorf("ListByUser: got %d, want 2", len(creds))
	}
}

func TestCredentialStore_CountByUser(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteCredentialStore(database)
	ctx := context.Background()

	tests := []struct {
		name      string
		userID    string
		insert    int
		wantCount int
	}{
		{"no credentials", "user-empty", 0, 0},
		{"one credential", "user-one", 1, 1},
		{"two credentials", "user-two", 2, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			insertUser(t, database, tc.userID)
			for i := 0; i < tc.insert; i++ {
				id := tc.userID + "-cred-" + string(rune('0'+i))
				if err := store.Create(ctx, makeTestCredential(t, id, tc.userID)); err != nil {
					t.Fatalf("Create: %v", err)
				}
			}

			count, err := store.CountByUser(ctx, tc.userID)
			if err != nil {
				t.Fatalf("CountByUser: %v", err)
			}
			if count != tc.wantCount {
				t.Errorf("CountByUser: got %d, want %d", count, tc.wantCount)
			}
		})
	}
}

func TestCredentialStore_UpdateSignCount(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteCredentialStore(database)
	ctx := context.Background()

	insertUser(t, database, "user-sc")
	cred := makeTestCredential(t, "cred-sc", "user-sc")
	if err := store.Create(ctx, cred); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.UpdateSignCount(ctx, "cred-sc", 42); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}

	got, err := store.GetByID(ctx, "cred-sc")
	if err != nil {
		t.Fatalf("GetByID after update: %v", err)
	}
	if got.SignCount != 42 {
		t.Errorf("SignCount: got %d, want 42", got.SignCount)
	}
	if got.LastUsedAt == nil {
		t.Error("LastUsedAt: expected non-nil after UpdateSignCount")
	}
}

func TestCredentialStore_UpdateSignCount_NotFound(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteCredentialStore(database)
	ctx := context.Background()

	err := store.UpdateSignCount(ctx, "ghost", 1)
	if err == nil {
		t.Fatal("expected error for nonexistent credential, got nil")
	}
}

func TestCredentialStore_Delete(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteCredentialStore(database)
	ctx := context.Background()

	insertUser(t, database, "user-del")
	cred := makeTestCredential(t, "cred-del", "user-del")
	if err := store.Create(ctx, cred); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Delete(ctx, "cred-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.GetByID(ctx, "cred-del")
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestCredentialStore_Delete_NotFound(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteCredentialStore(database)
	ctx := context.Background()

	err := store.Delete(ctx, "never-existed")
	if err == nil {
		t.Fatal("expected error deleting nonexistent credential, got nil")
	}
}

// ─── ChallengeStore tests ─────────────────────────────────────────────────────

func TestChallengeStore_RegistrationRoundTrip(t *testing.T) {
	store := webauthn.NewChallengeStore()

	data := gowebauthn.SessionData{Challenge: "test-challenge-reg"}
	store.SetRegistration("session-1", data)

	got, err := store.GetRegistration("session-1")
	if err != nil {
		t.Fatalf("GetRegistration: %v", err)
	}
	if got.Challenge != data.Challenge {
		t.Errorf("Challenge: got %q, want %q", got.Challenge, data.Challenge)
	}

	// Second get should fail (consumed).
	_, err = store.GetRegistration("session-1")
	if err == nil {
		t.Fatal("expected error on second get, got nil")
	}
}

func TestChallengeStore_AuthenticationRoundTrip(t *testing.T) {
	store := webauthn.NewChallengeStore()

	data := gowebauthn.SessionData{Challenge: "test-challenge-auth"}
	store.SetAuthentication("session-2", data)

	got, err := store.GetAuthentication("session-2")
	if err != nil {
		t.Fatalf("GetAuthentication: %v", err)
	}
	if got.Challenge != data.Challenge {
		t.Errorf("Challenge: got %q, want %q", got.Challenge, data.Challenge)
	}
}

func TestChallengeStore_NotFound(t *testing.T) {
	store := webauthn.NewChallengeStore()

	_, err := store.GetRegistration("missing")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestChallengeStore_CrossPrefixIsolation(t *testing.T) {
	store := webauthn.NewChallengeStore()

	data := gowebauthn.SessionData{Challenge: "same-id"}
	store.SetRegistration("key-x", data)

	// Auth with same key should not find the registration entry.
	_, err := store.GetAuthentication("key-x")
	if err == nil {
		t.Fatal("expected error: auth prefix should not match reg entry")
	}
}

func TestChallengeStore_Expiry(t *testing.T) {
	// Use a very short TTL so we can test expiry without sleeping long.
	store := webauthn.NewChallengeStoreWithTTL(1 * time.Millisecond)

	data := gowebauthn.SessionData{Challenge: "expiry-test"}
	store.SetRegistration("session-exp", data)

	time.Sleep(5 * time.Millisecond)

	_, err := store.GetRegistration("session-exp")
	if err == nil {
		t.Fatal("expected error for expired challenge, got nil")
	}
}
