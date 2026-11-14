package authlog_test

import (
	"context"
	"testing"
	"time"

	"github.com/crueber/passage/internal/authlog"
	"github.com/crueber/passage/internal/testutil"
)

// baseTime is a fixed instant so ordering assertions never depend on the clock.
var baseTime = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

// appendEvent is a test helper that writes one event with a derived timestamp.
func appendEvent(t *testing.T, store *authlog.Store, i int, e authlog.Event) *authlog.Event {
	t.Helper()

	if e.CreatedAt.IsZero() {
		e.CreatedAt = baseTime.Add(time.Duration(i) * time.Minute)
	}
	if err := store.Append(context.Background(), &e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	return &e
}

func TestStore_AppendFillsIDAndCreatedAt(t *testing.T) {
	t.Parallel()
	database := testutil.NewTestDB(t)
	store := authlog.NewStore(database)
	ctx := context.Background()

	e := &authlog.Event{
		Event:    authlog.EventLoginSuccess,
		Outcome:  authlog.OutcomeSuccess,
		Username: "alice",
	}
	if err := store.Append(ctx, e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e.ID == "" {
		t.Error("Append: ID was not populated")
	}
	if e.CreatedAt.IsZero() {
		t.Error("Append: CreatedAt was not populated")
	}

	got, err := store.List(ctx, authlog.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List: got %d events, want 1", len(got))
	}
	if got[0].Event != authlog.EventLoginSuccess || got[0].Username != "alice" {
		t.Errorf("List: got %+v", got[0])
	}
	if got[0].CreatedAt.IsZero() {
		t.Error("List: CreatedAt scanned as zero")
	}
}

func TestStore_List_NewestFirst(t *testing.T) {
	t.Parallel()
	database := testutil.NewTestDB(t)
	store := authlog.NewStore(database)

	for i := 0; i < 3; i++ {
		appendEvent(t, store, i, authlog.Event{Event: authlog.EventLoginSuccess, Outcome: authlog.OutcomeSuccess})
	}

	got, err := store.List(context.Background(), authlog.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List: got %d events, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if !got[i-1].CreatedAt.After(got[i].CreatedAt) {
			t.Errorf("List: not newest first at %d: %v then %v", i, got[i-1].CreatedAt, got[i].CreatedAt)
		}
	}
}

func TestStore_Filters(t *testing.T) {
	t.Parallel()

	type want struct {
		count int
	}

	tests := []struct {
		name   string
		filter authlog.Filter
		want   want
	}{
		{
			name:   "no filter",
			filter: authlog.Filter{},
			want:   want{count: 5},
		},
		{
			name:   "by event",
			filter: authlog.Filter{Event: authlog.EventLoginFailure},
			want:   want{count: 2},
		},
		{
			name:   "by outcome",
			filter: authlog.Filter{Outcome: authlog.OutcomeSuccess},
			want:   want{count: 3},
		},
		{
			name:   "username substring",
			filter: authlog.Filter{Username: "ali"},
			want:   want{count: 3},
		},
		{
			name:   "username substring is case insensitive",
			filter: authlog.Filter{Username: "ALICE"},
			want:   want{count: 3},
		},
		{
			name:   "username wildcard is literal",
			filter: authlog.Filter{Username: "100%"},
			want:   want{count: 1},
		},
		{
			name:   "since is inclusive",
			filter: authlog.Filter{Since: baseTime.Add(2 * time.Minute)},
			want:   want{count: 3},
		},
		{
			name:   "combined",
			filter: authlog.Filter{Event: authlog.EventLoginFailure, Outcome: authlog.OutcomeFailure, Username: "ali", Since: baseTime},
			want:   want{count: 2},
		},
		{
			name:   "no matches",
			filter: authlog.Filter{Event: authlog.EventPasskeyLogin},
			want:   want{count: 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			database := testutil.NewTestDB(t)
			store := authlog.NewStore(database)

			// Five representative events. The "100% legit" username proves
			// LIKE wildcards in user input are escaped.
			appendEvent(t, store, 0, authlog.Event{Event: authlog.EventLoginSuccess, Outcome: authlog.OutcomeSuccess, Username: "alice"})
			appendEvent(t, store, 1, authlog.Event{Event: authlog.EventLoginSuccess, Outcome: authlog.OutcomeSuccess, Username: "100% legit"})
			appendEvent(t, store, 2, authlog.Event{Event: authlog.EventLoginFailure, Outcome: authlog.OutcomeFailure, Username: "alice"})
			appendEvent(t, store, 3, authlog.Event{Event: authlog.EventLoginFailure, Outcome: authlog.OutcomeFailure, Username: "alice-admin"})
			appendEvent(t, store, 4, authlog.Event{Event: authlog.EventLogout, Outcome: authlog.OutcomeSuccess, Username: "bob"})

			listed, err := store.List(context.Background(), tc.filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(listed) != tc.want.count {
				t.Errorf("List: got %d events, want %d", len(listed), tc.want.count)
			}

			count, err := store.Count(context.Background(), tc.filter)
			if err != nil {
				t.Fatalf("Count: %v", err)
			}
			if count != tc.want.count {
				t.Errorf("Count: got %d, want %d", count, tc.want.count)
			}
		})
	}
}

func TestStore_List_Pagination(t *testing.T) {
	t.Parallel()
	database := testutil.NewTestDB(t)
	store := authlog.NewStore(database)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		appendEvent(t, store, i, authlog.Event{Event: authlog.EventLoginSuccess, Outcome: authlog.OutcomeSuccess})
	}

	tests := []struct {
		name string
		f    authlog.Filter
		want int
	}{
		{name: "first page", f: authlog.Filter{Limit: 2, Offset: 0}, want: 2},
		{name: "second page", f: authlog.Filter{Limit: 2, Offset: 2}, want: 2},
		{name: "last partial page", f: authlog.Filter{Limit: 2, Offset: 4}, want: 1},
		{name: "offset past end", f: authlog.Filter{Limit: 2, Offset: 99}, want: 0},
		{name: "negative offset is zero", f: authlog.Filter{Limit: 2, Offset: -7}, want: 2},
		{name: "zero limit uses default", f: authlog.Filter{Limit: 0}, want: 5},
		{name: "negative limit uses default", f: authlog.Filter{Limit: -1}, want: 5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.List(ctx, tc.f)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("List: got %d events, want %d", len(got), tc.want)
			}
		})
	}

	// Count ignores pagination.
	count, err := store.Count(ctx, authlog.Filter{Limit: 1, Offset: 4})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 5 {
		t.Errorf("Count with pagination: got %d, want 5", count)
	}
}

func TestStore_PurgeBefore(t *testing.T) {
	t.Parallel()
	database := testutil.NewTestDB(t)
	store := authlog.NewStore(database)
	ctx := context.Background()

	appendEvent(t, store, 0, authlog.Event{Event: authlog.EventLoginSuccess})
	appendEvent(t, store, 1, authlog.Event{Event: authlog.EventLoginSuccess})
	appendEvent(t, store, 2, authlog.Event{Event: authlog.EventLoginSuccess})

	cutoff := baseTime.Add(1 * time.Minute)
	removed, err := store.PurgeBefore(ctx, cutoff)
	if err != nil {
		t.Fatalf("PurgeBefore: %v", err)
	}
	if removed != 1 {
		t.Errorf("PurgeBefore: removed %d rows, want 1", removed)
	}

	remaining, err := store.List(ctx, authlog.Filter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("after purge: got %d events, want 2", len(remaining))
	}
	for _, e := range remaining {
		if e.CreatedAt.Before(cutoff) {
			t.Errorf("after purge: retained event older than cutoff: %v", e.CreatedAt)
		}
	}
}
