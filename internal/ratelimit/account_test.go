package ratelimit_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/ratelimit"
	"github.com/crueber/passage/internal/testutil"
)

// testClock is a manually advanced clock so these tests never sleep.
type testClock struct {
	t time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time { return c.t }

func (c *testClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// newAccountFixture builds a real in-memory SQLite-backed store and service.
func newAccountFixture(t *testing.T, maxFailures int, lockout time.Duration) (*ratelimit.AccountStore, *ratelimit.AccountService, *testClock) {
	t.Helper()
	db := testutil.NewTestDB(t)
	store := ratelimit.NewAccountStore(db)
	clock := newTestClock()
	svc := ratelimit.NewAccountService(store, ratelimit.AccountConfig{
		MaxFailures: maxFailures,
		Lockout:     lockout,
	}, clock.Now)
	return store, svc, clock
}

func TestAccountService_LockoutLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("threshold locks the account and resets the counter", func(t *testing.T) {
		t.Parallel()
		store, svc, clock := newAccountFixture(t, 3, 15*time.Minute)

		for i := 1; i < 3; i++ {
			status, err := svc.RecordFailure(ctx, "alice")
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

		status, err := svc.RecordFailure(ctx, "alice")
		if err != nil {
			t.Fatalf("RecordFailure threshold: %v", err)
		}
		if !status.Locked {
			t.Fatal("threshold failure did not lock the account")
		}
		if status.Remaining != 15*time.Minute {
			t.Errorf("Remaining = %v, want %v", status.Remaining, 15*time.Minute)
		}

		state, err := store.Get(ctx, "alice")
		if err != nil {
			t.Fatalf("Get after lock: %v", err)
		}
		if state.Failures != 0 {
			t.Errorf("persisted Failures = %d, want 0 after lock", state.Failures)
		}
		if want := clock.Now().Add(15 * time.Minute); !state.LockedUntil.Equal(want) {
			t.Errorf("LockedUntil = %v, want %v", state.LockedUntil, want)
		}

		status, err = svc.Status(ctx, "alice")
		if err != nil {
			t.Fatalf("Status while locked: %v", err)
		}
		if !status.Locked || status.Remaining != 15*time.Minute {
			t.Errorf("Status = %+v, want locked for 15m", status)
		}
	})

	t.Run("a locked account rejects failures without extending the lock", func(t *testing.T) {
		t.Parallel()
		store, svc, clock := newAccountFixture(t, 2, 10*time.Minute)

		for i := 0; i < 2; i++ {
			if _, err := svc.RecordFailure(ctx, "bob"); err != nil {
				t.Fatalf("RecordFailure %d: %v", i, err)
			}
		}
		before, err := store.Get(ctx, "bob")
		if err != nil {
			t.Fatalf("Get after lock: %v", err)
		}

		// A caller that skips Status and records another failure must still be
		// rejected; the lock must not be pushed further into the future.
		status, err := svc.RecordFailure(ctx, "bob")
		if err != nil {
			t.Fatalf("RecordFailure while locked: %v", err)
		}
		if !status.Locked {
			t.Fatal("failure during lock was accepted")
		}

		after, err := store.Get(ctx, "bob")
		if err != nil {
			t.Fatalf("Get after rejected failure: %v", err)
		}
		if !after.LockedUntil.Equal(before.LockedUntil) {
			t.Errorf("lock extended by rejected failure: %v -> %v", before.LockedUntil, after.LockedUntil)
		}
		if after.Failures != 0 {
			t.Errorf("Failures = %d, want 0 after rejected failure", after.Failures)
		}

		// The clock has not moved, so the remaining time is unchanged.
		clock.Advance(time.Second)
		status, err = svc.Status(ctx, "bob")
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if !status.Locked {
			t.Fatal("account unlocked without advancing past the lockout")
		}
	})

	t.Run("lock expires at read time and the next failure starts fresh", func(t *testing.T) {
		t.Parallel()
		store, svc, clock := newAccountFixture(t, 2, 5*time.Minute)

		for i := 0; i < 2; i++ {
			if _, err := svc.RecordFailure(ctx, "carol"); err != nil {
				t.Fatalf("RecordFailure %d: %v", i, err)
			}
		}

		clock.Advance(5*time.Minute + time.Second)

		status, err := svc.Status(ctx, "carol")
		if err != nil {
			t.Fatalf("Status after expiry: %v", err)
		}
		if status.Locked {
			t.Fatalf("Status still locked after expiry: %+v", status)
		}
		if status.Failures != 0 {
			t.Errorf("Failures = %d, want 0 after expiry", status.Failures)
		}

		state, err := store.Get(ctx, "carol")
		if err != nil {
			t.Fatalf("Get after expiry: %v", err)
		}
		if !state.LockedUntil.IsZero() {
			t.Errorf("LockedUntil = %v, want cleared", state.LockedUntil)
		}

		status, err = svc.RecordFailure(ctx, "carol")
		if err != nil {
			t.Fatalf("RecordFailure after expiry: %v", err)
		}
		if status.Locked || status.Failures != 1 {
			t.Errorf("post-expiry failure = %+v, want one fresh failure", status)
		}
	})

	t.Run("success before the threshold clears the counter", func(t *testing.T) {
		t.Parallel()
		store, svc, _ := newAccountFixture(t, 5, 15*time.Minute)

		for i := 0; i < 4; i++ {
			if _, err := svc.RecordFailure(ctx, "dave"); err != nil {
				t.Fatalf("RecordFailure %d: %v", i, err)
			}
		}
		if err := svc.Reset(ctx, "dave"); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		if _, err := store.Get(ctx, "dave"); !errors.Is(err, ratelimit.ErrNotFound) {
			t.Fatalf("Get after Reset = %v, want ErrNotFound", err)
		}

		status, err := svc.Status(ctx, "dave")
		if err != nil {
			t.Fatalf("Status after Reset: %v", err)
		}
		if status.Locked || status.Failures != 0 {
			t.Errorf("Status after Reset = %+v, want clean", status)
		}
	})

	t.Run("unknown usernames are throttled identically", func(t *testing.T) {
		t.Parallel()

		usernames := []string{"alice", "ghost"}
		results := make(map[string]ratelimit.AccountStatus, len(usernames))

		for _, username := range usernames {
			store, svc, clock := newAccountFixture(t, 2, 15*time.Minute)
			for i := 0; i < 2; i++ {
				if _, err := svc.RecordFailure(ctx, username); err != nil {
					t.Fatalf("%s RecordFailure %d: %v", username, i, err)
				}
			}
			status, err := svc.Status(ctx, username)
			if err != nil {
				t.Fatalf("%s Status: %v", username, err)
			}
			if !status.Locked || status.Remaining != 15*time.Minute {
				t.Errorf("%s Status = %+v, want locked for 15m", username, status)
			}
			state, err := store.Get(ctx, username)
			if err != nil {
				t.Fatalf("%s Get: %v", username, err)
			}
			if state.Failures != 0 || state.LockedUntil.IsZero() {
				t.Errorf("%s state = %+v, want locked row", username, state)
			}
			results[username] = status
			clock.Advance(time.Minute)
		}

		if results["alice"] != results["ghost"] {
			t.Errorf("known and unknown lock status differ: %+v vs %+v", results["alice"], results["ghost"])
		}
	})

	t.Run("usernames share one bucket regardless of case", func(t *testing.T) {
		t.Parallel()
		store, svc, _ := newAccountFixture(t, 2, 15*time.Minute)

		if _, err := svc.RecordFailure(ctx, "Admin"); err != nil {
			t.Fatalf("RecordFailure Admin: %v", err)
		}
		status, err := svc.RecordFailure(ctx, "admin")
		if err != nil {
			t.Fatalf("RecordFailure admin: %v", err)
		}
		if !status.Locked {
			t.Fatal("Admin and admin did not share a failure bucket")
		}

		status, err = svc.Status(ctx, "ADMIN")
		if err != nil {
			t.Fatalf("Status ADMIN: %v", err)
		}
		if !status.Locked {
			t.Errorf("Status ADMIN = %+v, want locked", status)
		}
		if status.Remaining != 15*time.Minute {
			t.Errorf("Status ADMIN Remaining = %v, want 15m", status.Remaining)
		}

		state, err := store.Get(ctx, "aDmIn")
		if err != nil {
			t.Fatalf("Get mixed case: %v", err)
		}
		if state.Username != "admin" {
			t.Errorf("stored username = %q, want %q", state.Username, "admin")
		}
	})

	t.Run("overlong usernames are bounded and share a bucket", func(t *testing.T) {
		t.Parallel()
		store, svc, _ := newAccountFixture(t, 2, 15*time.Minute)

		long := strings.Repeat("a", 10000)
		for i := 0; i < 2; i++ {
			if _, err := svc.RecordFailure(ctx, long); err != nil {
				t.Fatalf("RecordFailure %d: %v", i, err)
			}
		}
		status, err := svc.Status(ctx, long)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if !status.Locked {
			t.Fatal("overlong username was not throttled")
		}

		state, err := store.Get(ctx, long)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(state.Username) != 128 {
			t.Errorf("stored key length = %d, want 128", len(state.Username))
		}

		// Everything after the cap shares the same bucket.
		status, err = svc.Status(ctx, strings.Repeat("a", 128)+"-different-tail")
		if err != nil {
			t.Fatalf("Status alternate tail: %v", err)
		}
		if !status.Locked {
			t.Error("truncated key did not share the original bucket")
		}
	})
}

func TestAccountService_Disabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name    string
		max     int
		lockout time.Duration
	}{
		{name: "zero failure threshold", max: 0, lockout: 15 * time.Minute},
		{name: "zero lockout", max: 5, lockout: 0},
		{name: "both zero", max: 0, lockout: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store, svc, _ := newAccountFixture(t, tc.max, tc.lockout)

			if svc.Enabled() {
				t.Fatal("Enabled() = true, want false")
			}
			for i := 0; i < 10; i++ {
				status, err := svc.RecordFailure(ctx, "eve")
				if err != nil {
					t.Fatalf("RecordFailure %d: %v", i, err)
				}
				if status.Locked {
					t.Fatalf("failure %d locked a disabled throttle", i)
				}
			}
			if _, err := store.Get(ctx, "eve"); !errors.Is(err, ratelimit.ErrNotFound) {
				t.Errorf("Get = %v, want ErrNotFound when disabled", err)
			}
			status, err := svc.Status(ctx, "eve")
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if status.Locked {
				t.Errorf("Status = %+v, want unlocked when disabled", status)
			}
			if err := svc.Reset(ctx, "eve"); err != nil {
				t.Errorf("Reset when disabled: %v", err)
			}
			locked, err := svc.ListLocked(ctx)
			if err != nil {
				t.Fatalf("ListLocked: %v", err)
			}
			if len(locked) != 0 {
				t.Errorf("ListLocked = %v, want empty when disabled", locked)
			}
		})
	}
}

func TestAccountStore_ListLocked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, svc, clock := newAccountFixture(t, 5, 15*time.Minute)

	now := clock.Now()
	if err := store.Lock(ctx, "alice", now.Add(10*time.Minute)); err != nil {
		t.Fatalf("lock alice: %v", err)
	}
	if err := store.Lock(ctx, "zoe", now.Add(20*time.Minute)); err != nil {
		t.Fatalf("lock zoe: %v", err)
	}
	if err := store.Lock(ctx, "expired", now.Add(-time.Minute)); err != nil {
		t.Fatalf("lock expired: %v", err)
	}
	if _, err := store.RecordFailure(ctx, "counting"); err != nil {
		t.Fatalf("record failure: %v", err)
	}

	locked, err := store.ListLocked(ctx, now)
	if err != nil {
		t.Fatalf("ListLocked: %v", err)
	}
	if len(locked) != 2 {
		t.Fatalf("ListLocked returned %d rows, want 2: %+v", len(locked), locked)
	}
	if locked[0].Username != "alice" || locked[1].Username != "zoe" {
		t.Errorf("ListLocked order = %q, %q; want soonest-unlock first", locked[0].Username, locked[1].Username)
	}

	// The service applies its injected clock, so advancing past a lock drops it.
	svcLocked, err := svc.ListLocked(ctx)
	if err != nil {
		t.Fatalf("service ListLocked: %v", err)
	}
	if len(svcLocked) != 2 {
		t.Fatalf("service ListLocked returned %d rows, want 2", len(svcLocked))
	}
	clock.Advance(11 * time.Minute)
	svcLocked, err = svc.ListLocked(ctx)
	if err != nil {
		t.Fatalf("service ListLocked after advance: %v", err)
	}
	if len(svcLocked) != 1 || svcLocked[0].Username != "zoe" {
		t.Errorf("service ListLocked after advance = %+v, want only zoe", svcLocked)
	}

	clock.Advance(10 * time.Minute)
	svcLocked, err = svc.ListLocked(ctx)
	if err != nil {
		t.Fatalf("service ListLocked after all expiry: %v", err)
	}
	if len(svcLocked) != 0 {
		t.Errorf("service ListLocked = %+v, want empty after all locks expire", svcLocked)
	}
}
