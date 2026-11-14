package session_test

import (
	"context"
	"testing"

	"github.com/crueber/passage/internal/session"
)

// countingSessions is a SessionCounter that records how often it was called.
type countingSessions struct {
	created int
	revoked int
}

func (c *countingSessions) SessionCreated() { c.created++ }
func (c *countingSessions) SessionRevoked() { c.revoked++ }

// TestSessionCounter verifies the optional metrics hook: created sessions and
// successful explicit revokes are counted, failed revokes are not, and a nil
// counter (the default) changes nothing.
func TestSessionCounter(t *testing.T) {
	t.Parallel()
	_, _, svc, u := setup(t)
	ctx := context.Background()

	counter := &countingSessions{}
	svc.SetSessionCounter(counter)

	sess, err := svc.NewSession(ctx, u.ID, nil, "127.0.0.1", "TestAgent/1.0")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if counter.created != 1 {
		t.Errorf("created = %d, want 1", counter.created)
	}

	if err := svc.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if counter.revoked != 1 {
		t.Errorf("revoked = %d, want 1", counter.revoked)
	}

	// Revoking a session that is already gone fails and must not be counted.
	if err := svc.RevokeSession(ctx, sess.ID); err == nil {
		t.Fatal("RevokeSession of a deleted session: expected an error")
	}
	if counter.revoked != 1 {
		t.Errorf("revoked = %d after a failed revoke, want 1", counter.revoked)
	}

	// A bulk revoke is one operation.
	if err := svc.RevokeAllByUser(ctx, u.ID); err != nil {
		t.Fatalf("RevokeAllByUser: %v", err)
	}
	if counter.revoked != 2 {
		t.Errorf("revoked = %d after bulk revoke, want 2", counter.revoked)
	}

	// RevokeByPublicID counts too.
	sess2, err := svc.NewSession(ctx, u.ID, nil, "", "")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := svc.RevokeSessionByPublicID(ctx, sess2.PublicID); err != nil {
		t.Fatalf("RevokeSessionByPublicID: %v", err)
	}
	if counter.created != 2 || counter.revoked != 3 {
		t.Errorf("created = %d, revoked = %d; want 2 created and 3 revoked", counter.created, counter.revoked)
	}
}

// TestSessionCounter_NilIsSafe documents that the hook is optional.
func TestSessionCounter_NilIsSafe(t *testing.T) {
	t.Parallel()
	_, _, svc, u := setup(t)
	ctx := context.Background()

	sess, err := svc.NewSession(ctx, u.ID, nil, "", "")
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := svc.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
}

// Ensure the service still satisfies interface expectations after the hook was
// added: this is a compile-time assertion that the counter is optional.
var _ session.SessionCounter = (*countingSessions)(nil)
