package webauthn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/testutil"
	"github.com/crueber/passage/internal/user"
)

func marshalTestWACred(t *testing.T, id string, signCount uint32) []byte {
	t.Helper()
	b, err := json.Marshal(gowebauthn.Credential{
		ID:        []byte(id),
		PublicKey: []byte("test-public-key-" + id),
		Authenticator: gowebauthn.Authenticator{
			SignCount: signCount,
		},
	})
	if err != nil {
		t.Fatalf("marshal test credential: %v", err)
	}
	return b
}

func TestDBCredsToWACredsPreservesSignCount(t *testing.T) {
	u := &user.User{
		ID:       "user-signcount",
		Username: "alice",
		Name:     "Alice",
		IsActive: true,
	}

	tests := []struct {
		name           string
		dbCreds        []*Credential
		wantSignCounts []uint32
		wantErr        bool
	}{
		{
			name: "zero in json blob is overridden by persisted non-zero sign count",
			dbCreds: []*Credential{
				{
					ID:        "cred-1",
					UserID:    u.ID,
					PublicKey: marshalTestWACred(t, "cred-1", 0),
					SignCount: 42,
				},
			},
			wantSignCounts: []uint32{42},
		},
		{
			name: "stale json sign count is overridden by newer persisted sign count",
			dbCreds: []*Credential{
				{
					ID:        "cred-2",
					UserID:    u.ID,
					PublicKey: marshalTestWACred(t, "cred-2", 5),
					SignCount: 19,
				},
			},
			wantSignCounts: []uint32{19},
		},
		{
			name: "multiple credentials preserve distinct sign counts",
			dbCreds: []*Credential{
				{
					ID:        "cred-a",
					UserID:    u.ID,
					PublicKey: marshalTestWACred(t, "cred-a", 0),
					SignCount: 7,
				},
				{
					ID:        "cred-b",
					UserID:    u.ID,
					PublicKey: marshalTestWACred(t, "cred-b", 3),
					SignCount: 105,
				},
			},
			wantSignCounts: []uint32{7, 105},
		},
		{
			name: "invalid json returns error",
			dbCreds: []*Credential{
				{
					ID:        "cred-bad",
					UserID:    u.ID,
					PublicKey: []byte("{invalid-json"),
					SignCount: 10,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waCreds, err := dbCredsToWACreds(tt.dbCreds)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("dbCredsToWACreds: %v", err)
			}

			waUser := NewWebAuthnUser(u, waCreds)
			got := waUser.WebAuthnCredentials()
			if len(got) != len(tt.wantSignCounts) {
				t.Fatalf("len(WebAuthnCredentials) = %d, want %d", len(got), len(tt.wantSignCounts))
			}

			for i, want := range tt.wantSignCounts {
				if got[i].Authenticator.SignCount != want {
					t.Errorf("cred[%d].Authenticator.SignCount = %d, want %d", i, got[i].Authenticator.SignCount, want)
				}

				// Verify clone detection is active: a non-increasing counter
				// triggers CloneWarning, while a strictly greater counter does not.
				cloned := got[i]
				cloned.Authenticator.UpdateCounter(want)
				if !cloned.Authenticator.CloneWarning {
					t.Errorf("cred[%d]: UpdateCounter(%d) against stored %d did not set CloneWarning", i, want, want)
				}

				advanced := got[i]
				advanced.Authenticator.UpdateCounter(want + 1)
				if advanced.Authenticator.CloneWarning {
					t.Errorf("cred[%d]: UpdateCounter(%d) against stored %d unexpectedly set CloneWarning", i, want+1, want)
				}
				if advanced.Authenticator.SignCount != want+1 {
					t.Errorf("cred[%d]: SignCount after advance = %d, want %d", i, advanced.Authenticator.SignCount, want+1)
				}
			}
		})
	}
}

func TestUserCredentialsPreservesUpdatedSQLiteSignCount(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewTestDB(t)

	userStore := user.NewStore(db)
	u := &user.User{
		ID:           "user-sqlite-signcount",
		Username:     "bob",
		Email:        "bob@example.com",
		PasswordHash: "hash",
		IsActive:     true,
	}
	if err := userStore.Create(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	credStore := NewSQLiteCredentialStore(db)
	rawID := []byte("sqlite-cred-id")
	credID := base64.RawURLEncoding.EncodeToString(rawID)

	// Simulate registration: public_key JSON has SignCount 0 and DB row starts at 0.
	if err := credStore.Create(ctx, &Credential{
		ID:        credID,
		UserID:    u.ID,
		Name:      "YubiKey",
		PublicKey: marshalTestWACred(t, string(rawID), 0),
		SignCount: 0,
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	// Simulate a successful login updating only the sign_count column in SQLite
	// (leaving the stored public_key JSON blob unchanged at SignCount 0).
	const persistedCount uint32 = 17
	if err := credStore.UpdateSignCount(ctx, credID, persistedCount); err != nil {
		t.Fatalf("update sign count: %v", err)
	}

	h := &Handler{credStore: credStore}
	waCreds, err := h.userCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("userCredentials: %v", err)
	}

	waUser := NewWebAuthnUser(u, waCreds)
	got := waUser.WebAuthnCredentials()
	if len(got) != 1 {
		t.Fatalf("len(WebAuthnCredentials) = %d, want 1", len(got))
	}
	if got[0].Authenticator.SignCount != persistedCount {
		t.Fatalf("WebAuthnCredentials()[0].Authenticator.SignCount = %d, want %d", got[0].Authenticator.SignCount, persistedCount)
	}

	// A replayed/lower counter from a cloned authenticator must trigger CloneWarning.
	got[0].Authenticator.UpdateCounter(persistedCount - 1)
	if !got[0].Authenticator.CloneWarning {
		t.Fatal("expected CloneWarning=true for counter lower than persisted SignCount")
	}
}
