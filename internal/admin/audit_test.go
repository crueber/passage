package admin_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/testutil"
)

// ─── SQLiteAuditStore tests ───────────────────────────────────────────────────

func TestAuditStore_Create_and_List(t *testing.T) {
	t.Parallel()
	database := testutil.NewTestDB(t)
	store := admin.NewSQLiteAuditStore(database)
	ctx := context.Background()

	// We need a valid user ID since actor_id is a FK reference to users(id).
	// Use the settings store (same DB) to ensure migrations ran, and create a
	// user directly via SQL for test setup.
	_, err := database.ExecContext(ctx, `
		INSERT INTO users (id, username, email, password_hash, is_admin, is_active, roles, created_at, updated_at)
		VALUES ('actor-001', 'testadmin', 'testadmin@example.com', 'hash', 1, 1, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}

	events := []*admin.AuditEvent{
		{ActorID: "actor-001", ActorName: "testadmin", Action: admin.AuditActionUserCreate, TargetType: "user", TargetID: "user-001", TargetName: "alice", IPAddress: "127.0.0.1"},
		{ActorID: "actor-001", ActorName: "testadmin", Action: admin.AuditActionAppCreate, TargetType: "app", TargetID: "app-001", TargetName: "myapp", IPAddress: "127.0.0.1"},
		{ActorID: "actor-001", ActorName: "testadmin", Action: admin.AuditActionSettingsUpdate, TargetType: "settings", IPAddress: "10.0.0.1"},
	}

	for _, e := range events {
		if err := store.Create(ctx, e); err != nil {
			t.Fatalf("store.Create: %v", err)
		}
		if e.ID == "" {
			t.Error("Create: ID was not populated")
		}
	}

	listed, err := store.List(ctx, admin.AuditFilter{})
	if err != nil {
		t.Fatalf("store.List: %v", err)
	}

	if len(listed) != 3 {
		t.Errorf("List: got %d events, want 3", len(listed))
	}

	// Results are ordered DESC by created_at — last inserted first.
	if listed[0].Action != admin.AuditActionSettingsUpdate {
		t.Errorf("List[0].Action = %q, want %q", listed[0].Action, admin.AuditActionSettingsUpdate)
	}
}

func TestAuditStore_List_FilterByAction(t *testing.T) {
	t.Parallel()
	database := testutil.NewTestDB(t)
	store := admin.NewSQLiteAuditStore(database)
	ctx := context.Background()

	_, err := database.ExecContext(ctx, `
		INSERT INTO users (id, username, email, password_hash, is_admin, is_active, roles, created_at, updated_at)
		VALUES ('actor-002', 'filteradmin', 'filteradmin@example.com', 'hash', 1, 1, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`)
	if err != nil {
		t.Fatalf("insert test user: %v", err)
	}

	// Create events with two different actions.
	for i := 0; i < 3; i++ {
		if err := store.Create(ctx, &admin.AuditEvent{
			ActorID: "actor-002", ActorName: "filteradmin",
			Action: admin.AuditActionUserUpdate, TargetType: "user",
			IPAddress: "127.0.0.1",
		}); err != nil {
			t.Fatalf("Create user.update: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := store.Create(ctx, &admin.AuditEvent{
			ActorID: "actor-002", ActorName: "filteradmin",
			Action: admin.AuditActionAppDelete, TargetType: "app",
			IPAddress: "127.0.0.1",
		}); err != nil {
			t.Fatalf("Create app.delete: %v", err)
		}
	}

	// Filter by user.update — should return exactly 3.
	userUpdates, err := store.List(ctx, admin.AuditFilter{Action: admin.AuditActionUserUpdate})
	if err != nil {
		t.Fatalf("List(user.update): %v", err)
	}
	if len(userUpdates) != 3 {
		t.Errorf("List(user.update): got %d, want 3", len(userUpdates))
	}
	for _, e := range userUpdates {
		if e.Action != admin.AuditActionUserUpdate {
			t.Errorf("List(user.update): unexpected action %q", e.Action)
		}
	}

	// Filter by app.delete — should return exactly 2.
	appDeletes, err := store.List(ctx, admin.AuditFilter{Action: admin.AuditActionAppDelete})
	if err != nil {
		t.Fatalf("List(app.delete): %v", err)
	}
	if len(appDeletes) != 2 {
		t.Errorf("List(app.delete): got %d, want 2", len(appDeletes))
	}

	// Filter by an unknown action — should return 0.
	none, err := store.List(ctx, admin.AuditFilter{Action: "does.not.exist"})
	if err != nil {
		t.Fatalf("List(does.not.exist): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("List(does.not.exist): got %d, want 0", len(none))
	}
}

// ─── AuditService tests ───────────────────────────────────────────────────────

// errorAuditStore always returns an error from Create.
type errorAuditStore struct{}

func (errorAuditStore) Create(_ context.Context, _ *admin.AuditEvent) error {
	return errors.New("store: simulated failure")
}

func (errorAuditStore) List(_ context.Context, _ admin.AuditFilter) ([]*admin.AuditEvent, error) {
	return nil, errors.New("store: simulated failure")
}

func TestAuditService_Log_DoesNotPanic_OnStoreError(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := admin.NewAuditService(errorAuditStore{}, logger)

	// Must not panic — Log swallows errors and logs a warning.
	svc.Log(context.Background(), &admin.AuditEvent{
		ActorID:    "actor-x",
		ActorName:  "adminx",
		Action:     admin.AuditActionUserCreate,
		TargetType: "user",
		IPAddress:  "127.0.0.1",
	})
}
