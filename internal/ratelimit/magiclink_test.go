package ratelimit_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/testutil"
)

// newMagicLinkFixture builds a real in-memory SQLite-backed store and service
// whose clock the test advances by hand.
func newMagicLinkFixture(t *testing.T) (*ratelimit.MagicLinkStore, *ratelimit.MagicLinkService, *testClock) {
	t.Helper()
	db := testutil.NewTestDB(t)
	store := ratelimit.NewMagicLinkStore(db)
	clock := newTestClock()
	svc := ratelimit.NewMagicLinkService(store, ratelimit.MagicLinkConfig{
		MaxFailures: 3,
		Window:      24 * time.Hour,
		Lockout:     24 * time.Hour,
	}, clock.Now)
	return store, svc, clock
}

func TestMagicLinkService_BlocksAfterThreeFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, svc, clock := newMagicLinkFixture(t)
	const ip = "198.51.100.20"

	for i := 1; i <= 2; i++ {
		status, err := svc.RecordFailure(ctx, ip)
		if err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
		if status.Locked {
			t.Fatalf("RecordFailure %d locked too early", i)
		}
		if status.Failures != i {
			t.Errorf("failure %d: Failures = %d, want %d", i, status.Failures, i)
		}
	}

	status, err := svc.RecordFailure(ctx, ip)
	if err != nil {
		t.Fatalf("RecordFailure 3: %v", err)
	}
	if !status.Locked {
		t.Fatal("third failure did not block the address")
	}
	if status.Remaining < 24*time.Hour-time.Minute || status.Remaining > 24*time.Hour {
		t.Errorf("Remaining = %v, want about 24h", status.Remaining)
	}

	// Status and further failures agree, and a blocked address is not counted
	// again (the block does not extend on every request).
	again, err := svc.RecordFailure(ctx, ip)
	if err != nil {
		t.Fatalf("RecordFailure while blocked: %v", err)
	}
	if !again.Locked || again.Remaining < 23*time.Hour {
		t.Errorf("RecordFailure while blocked = %+v, want still locked", again)
	}

	clock.Advance(time.Hour)
	still, err := svc.Status(ctx, ip)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !still.Locked {
		t.Error("address unblocked after one hour; want locked for 24h")
	}

	clock.Advance(23*time.Hour + time.Minute)
	expired, err := svc.Status(ctx, ip)
	if err != nil {
		t.Fatalf("Status after 24h: %v", err)
	}
	if expired.Locked {
		t.Error("address still locked after 24 hours")
	}
}

func TestMagicLinkService_WindowResets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, svc, clock := newMagicLinkFixture(t)
	const ip = "198.51.100.21"

	// Two failures, then the window lapses: the next failure starts at one
	// instead of locking on a stale count.
	for i := 0; i < 2; i++ {
		if _, err := svc.RecordFailure(ctx, ip); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	clock.Advance(24*time.Hour + time.Minute)

	status, err := svc.RecordFailure(ctx, ip)
	if err != nil {
		t.Fatalf("RecordFailure after window: %v", err)
	}
	if status.Locked {
		t.Fatal("stale failures from a previous window blocked the address")
	}
	if status.Failures != 1 {
		t.Errorf("Failures = %d, want 1 (fresh window)", status.Failures)
	}
}

func TestMagicLinkService_FreshAddressIsClear(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, svc, _ := newMagicLinkFixture(t)

	status, err := svc.Status(ctx, "203.0.113.9")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Locked || status.Failures != 0 {
		t.Errorf("fresh address status = %+v, want zero value", status)
	}
}

func TestMagicLinkService_AddressesAreIndependent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	_, svc, _ := newMagicLinkFixture(t)

	for i := 0; i < 3; i++ {
		if _, err := svc.RecordFailure(ctx, "198.51.100.22"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
	status, err := svc.Status(ctx, "198.51.100.23")
	if err != nil {
		t.Fatalf("Status other address: %v", err)
	}
	if status.Locked {
		t.Error("blocking one address blocked another")
	}
}

func TestMagicLinkStore_PurgeExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store, svc, clock := newMagicLinkFixture(t)

	if _, err := svc.RecordFailure(ctx, "198.51.100.24"); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	// A block that is still active must survive a purge.
	for i := 0; i < 3; i++ {
		if _, err := svc.RecordFailure(ctx, "198.51.100.25"); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}

	clock.Advance(25 * time.Hour)
	if _, err := store.PurgeExpired(ctx, clock.Now().Add(-24*time.Hour)); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}

	if _, err := store.Get(ctx, "198.51.100.24"); !errors.Is(err, ratelimit.ErrNotFound) {
		t.Errorf("stale failure row survived the purge: %v", err)
	}
	if _, err := store.Get(ctx, "198.51.100.25"); err != nil {
		t.Errorf("active block row was purged: %v", err)
	}
}

func TestMagicLinkService_Disabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	db := testutil.NewTestDB(t)
	svc := ratelimit.NewMagicLinkService(ratelimit.NewMagicLinkStore(db), ratelimit.MagicLinkConfig{}, newTestClock().Now)

	for i := 0; i < 10; i++ {
		status, err := svc.RecordFailure(ctx, "198.51.100.26")
		if err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
		if status.Locked {
			t.Fatal("a zero config must not lock anything")
		}
	}
}
