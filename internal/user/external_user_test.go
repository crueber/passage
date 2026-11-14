package user_test

import (
	"context"
	"errors"
	"testing"

	"github.com/crueber/passage/internal/user"
)

// TestCreateExternalUser covers the account shape produced by an upstream
// identity provider: no password, verification copied from the provider, and a
// username that is always present.
func TestCreateExternalUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		preferred    string
		email        string
		verified     bool
		wantUsername string
		wantEmail    string
		wantVerified bool
		wantErr      error
	}{
		{
			name:         "preferred username",
			preferred:    "alice",
			email:        "Alice@Example.com",
			verified:     true,
			wantUsername: "alice",
			wantEmail:    "alice@example.com",
			wantVerified: true,
		},
		{
			name:         "derives from email local part",
			email:        "foo.bar@example.com",
			verified:     false,
			wantUsername: "foo_bar",
			wantEmail:    "foo.bar@example.com",
			wantVerified: false,
		},
		{
			name:         "sanitizes preferred username",
			preferred:    "Alice Smith!",
			email:        "alice@example.com",
			verified:     true,
			wantUsername: "Alice_Smith_",
			wantEmail:    "alice@example.com",
			wantVerified: true,
		},
		{
			name:      "empty email is refused",
			preferred: "alice",
			email:     "   ",
			wantErr:   user.ErrEmailRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := newUserService(t, true)

			u, err := svc.CreateExternalUser(context.Background(), tt.preferred, tt.email, "Alice", tt.verified)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("CreateExternalUser error = %v; want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateExternalUser: %v", err)
			}
			if u.PasswordHash != "" {
				t.Error("external user has a password hash; want none")
			}
			if u.Username != tt.wantUsername {
				t.Errorf("username = %q; want %q", u.Username, tt.wantUsername)
			}
			if u.Email != tt.wantEmail {
				t.Errorf("email = %q; want %q", u.Email, tt.wantEmail)
			}
			if u.EmailVerified != tt.wantVerified {
				t.Errorf("email_verified = %v; want %v", u.EmailVerified, tt.wantVerified)
			}
			if !u.IsActive {
				t.Error("external user should be active")
			}
		})
	}
}

// TestCreateExternalUser_UsernameCollision proves a collision gets a random
// suffix instead of failing the sign-in.
func TestCreateExternalUser_UsernameCollision(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	if _, err := svc.CreateExternalUser(ctx, "alice", "alice-one@example.com", "", true); err != nil {
		t.Fatalf("first CreateExternalUser: %v", err)
	}
	u, err := svc.CreateExternalUser(ctx, "alice", "alice-two@example.com", "", true)
	if err != nil {
		t.Fatalf("second CreateExternalUser: %v", err)
	}
	if u.Username == "alice" {
		t.Error("second user reused the colliding username; want a suffix")
	}
}

// TestCreateExternalUser_EmailCollision proves an existing address is refused
// rather than creating a second account for it.
func TestCreateExternalUser_EmailCollision(t *testing.T) {
	t.Parallel()
	svc := newUserService(t, true)
	ctx := context.Background()

	if _, err := svc.CreateExternalUser(ctx, "alice", "alice@example.com", "", true); err != nil {
		t.Fatalf("first CreateExternalUser: %v", err)
	}
	_, err := svc.CreateExternalUser(ctx, "different", "alice@example.com", "", true)
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Errorf("second CreateExternalUser error = %v; want ErrEmailTaken", err)
	}
}
