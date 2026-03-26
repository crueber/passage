package webauthn_test

import (
	"context"
	"errors"
	"testing"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/webauthn"
)

func TestSQLiteChallengeStore_SetAndGetRegistration(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteChallengeStore(database)

	data := gowebauthn.SessionData{Challenge: "reg-challenge-abc"}
	store.SetRegistration("session-reg-1", data)

	got, err := store.GetRegistration("session-reg-1")
	if err != nil {
		t.Fatalf("GetRegistration: %v", err)
	}
	if got.Challenge != data.Challenge {
		t.Errorf("Challenge: got %q, want %q", got.Challenge, data.Challenge)
	}

	// Second get must fail — single-use semantics.
	_, err = store.GetRegistration("session-reg-1")
	if err == nil {
		t.Fatal("expected error on second GetRegistration, got nil")
	}
}

func TestSQLiteChallengeStore_SetAndGetAuthentication(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteChallengeStore(database)

	data := gowebauthn.SessionData{Challenge: "auth-challenge-xyz"}
	store.SetAuthentication("session-auth-1", data)

	got, err := store.GetAuthentication("session-auth-1")
	if err != nil {
		t.Fatalf("GetAuthentication: %v", err)
	}
	if got.Challenge != data.Challenge {
		t.Errorf("Challenge: got %q, want %q", got.Challenge, data.Challenge)
	}

	// Second get must fail — single-use semantics.
	_, err = store.GetAuthentication("session-auth-1")
	if err == nil {
		t.Fatal("expected error on second GetAuthentication, got nil")
	}
}

func TestSQLiteChallengeStore_GetReturnsErrNotFound(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteChallengeStore(database)

	_, err := store.GetRegistration("does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	if !errors.Is(err, webauthn.ErrChallengeNotFound) {
		t.Errorf("expected ErrChallengeNotFound, got: %v", err)
	}
}

func TestSQLiteChallengeStore_GetReturnsErrExpired(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteChallengeStore(database)

	// Insert an already-expired row directly, bypassing SetRegistration so we
	// can control expires_at.
	expiredAt := time.Now().Add(-1 * time.Hour).UTC()
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO webauthn_challenges (id, session_data, expires_at, created_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		"reg:session-expired", `{"challenge":"expired-challenge"}`, expiredAt,
	)
	if err != nil {
		t.Fatalf("insert expired row: %v", err)
	}

	_, err = store.GetRegistration("session-expired")
	if err == nil {
		t.Fatal("expected error for expired challenge, got nil")
	}
	if !errors.Is(err, webauthn.ErrChallengeExpired) {
		t.Errorf("expected ErrChallengeExpired, got: %v", err)
	}
}

func TestSQLiteChallengeStore_CrossPrefixIsolation(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteChallengeStore(database)

	data := gowebauthn.SessionData{Challenge: "same-session-id"}
	store.SetRegistration("key-x", data)

	// GetAuthentication with the same session ID must not find the registration entry.
	_, err := store.GetAuthentication("key-x")
	if err == nil {
		t.Fatal("expected error: auth prefix should not match reg entry")
	}
	if !errors.Is(err, webauthn.ErrChallengeNotFound) {
		t.Errorf("expected ErrChallengeNotFound, got: %v", err)
	}
}

func TestSQLiteChallengeStore_DeleteExpired(t *testing.T) {
	database := testutil.NewTestDB(t)
	store := webauthn.NewSQLiteChallengeStore(database)
	ctx := context.Background()

	expiredAt := time.Now().Add(-1 * time.Hour).UTC()
	validAt := time.Now().Add(5 * time.Minute).UTC()

	// Insert one expired row and one valid row directly.
	for _, row := range []struct {
		id        string
		expiresAt time.Time
	}{
		{"reg:session-old", expiredAt},
		{"reg:session-new", validAt},
	} {
		_, err := database.ExecContext(ctx,
			`INSERT INTO webauthn_challenges (id, session_data, expires_at, created_at)
			 VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
			row.id, `{"challenge":"x"}`, row.expiresAt,
		)
		if err != nil {
			t.Fatalf("insert row %q: %v", row.id, err)
		}
	}

	if err := store.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	var count int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_challenges`).Scan(&count); err != nil {
		t.Fatalf("count after DeleteExpired: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row after DeleteExpired, got %d", count)
	}
}
