package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/crueber/passage/internal/admin"
	"github.com/crueber/passage/internal/testutil"
)

// TestAuditAPIAdapter verifies the wiring-layer mapping from the admin audit
// service to the REST API's record shape. The two packages deliberately do not
// import each other, so this adapter is the only place the fields are copied.
func TestAuditAPIAdapter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database := testutil.NewTestDB(t)
	logger := slog.New(slog.DiscardHandler)

	// audit_log.actor_id is a foreign key, and db.Open enables foreign keys.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO users (id, username, email) VALUES ('user-1', 'alice', 'alice@example.com')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	store := admin.NewSQLiteAuditStore(database)
	svc := admin.NewAuditService(store, logger)

	for _, action := range []string{"user.create", "app.create", "settings.update"} {
		svc.Log(ctx, &admin.AuditEvent{
			ActorID:    "user-1",
			ActorName:  "alice",
			Action:     action,
			TargetType: "thing",
			TargetID:   "thing-1",
			TargetName: "Thing",
			Detail:     "detail",
			IPAddress:  "192.0.2.5",
		})
	}

	adapter := &auditAPIAdapter{svc: svc}

	records, err := adapter.ListAudit(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	got := records[0]
	if got.ActorID != "user-1" || got.ActorName != "alice" {
		t.Errorf("actor = (%q, %q), want (user-1, alice)", got.ActorID, got.ActorName)
	}
	if got.TargetType != "thing" || got.TargetID != "thing-1" || got.TargetName != "Thing" {
		t.Errorf("target = %+v", got)
	}
	if got.Detail != "detail" || got.IPAddress != "192.0.2.5" {
		t.Errorf("detail/ip = (%q, %q)", got.Detail, got.IPAddress)
	}
	if got.CreatedAt.IsZero() {
		t.Error("created_at was not carried through the adapter")
	}

	// offset and limit are passed straight through to the audit store.
	page, err := adapter.ListAudit(ctx, 1, 1)
	if err != nil {
		t.Fatalf("ListAudit page: %v", err)
	}
	if len(page) != 1 {
		t.Fatalf("page size = %d, want 1", len(page))
	}
	if page[0].ID == got.ID {
		t.Error("offset did not advance the page")
	}
}
