package app_test

import (
	"context"
	"testing"

	"github.com/crueber/passage/internal/app"
	"github.com/crueber/passage/internal/user"
)

// newFavoriteFixture returns a store with one user granted access to two apps,
// plus the user store so a second user can share the same database.
func newFavoriteFixture(t *testing.T) (*app.SQLiteStore, *user.SQLiteStore, []*app.App, string) {
	t.Helper()
	ctx := context.Background()
	store, userStore := newTestStores(t)

	apps := []*app.App{
		{Slug: "grafana", Name: "Grafana", HostPattern: "grafana.example.com", IsActive: true},
		{Slug: "vault", Name: "Vault", HostPattern: "vault.example.com", IsActive: true},
	}
	for _, a := range apps {
		if err := store.Create(ctx, a); err != nil {
			t.Fatalf("create app %q: %v", a.Slug, err)
		}
	}
	u := createTestUserForApp(t, userStore, apps[0])
	for _, a := range apps {
		if err := store.GrantAccess(ctx, u.ID, a.ID); err != nil {
			t.Fatalf("grant access to %q: %v", a.Slug, err)
		}
	}
	return store, userStore, apps, u.ID
}

// TestStore_ToggleFavorite covers the star: each call flips the row, the
// returned state matches what was written, and the two apps stay independent.
func TestStore_ToggleFavorite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cases := []struct {
		name string
		app  int // index into the fixture apps
	}{
		{name: "first app", app: 0},
		{name: "second app", app: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store, _, apps, userID := newFavoriteFixture(t)
			target := apps[tc.app]
			other := apps[1-tc.app]

			favorite, found, err := store.ToggleFavorite(ctx, userID, target.ID)
			if err != nil {
				t.Fatalf("ToggleFavorite on: %v", err)
			}
			if !found || !favorite {
				t.Fatalf("ToggleFavorite on = (%v, %v), want (true, true)", favorite, found)
			}

			ids, err := store.FavoriteIDs(ctx, userID)
			if err != nil {
				t.Fatalf("FavoriteIDs: %v", err)
			}
			if !ids[target.ID] {
				t.Errorf("FavoriteIDs missing pinned app %q", target.Slug)
			}
			if ids[other.ID] {
				t.Errorf("FavoriteIDs included unpinned app %q", other.Slug)
			}

			favorite, found, err = store.ToggleFavorite(ctx, userID, target.ID)
			if err != nil {
				t.Fatalf("ToggleFavorite off: %v", err)
			}
			if !found || favorite {
				t.Fatalf("ToggleFavorite off = (%v, %v), want (false, true)", favorite, found)
			}

			ids, err = store.FavoriteIDs(ctx, userID)
			if err != nil {
				t.Fatalf("FavoriteIDs after unpin: %v", err)
			}
			if len(ids) != 0 {
				t.Errorf("FavoriteIDs after unpin = %v, want empty", ids)
			}
		})
	}
}

// TestStore_ToggleFavorite_NoAccess proves a toggle for an app the user cannot
// reach is a no-op rather than an error: the pin lives on the access row, so
// there is nothing to flip. It also covers an app id that does not exist.
func TestStore_ToggleFavorite_NoAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("app not granted", func(t *testing.T) {
		t.Parallel()
		store, _, apps, userID := newFavoriteFixture(t)
		if err := store.RevokeAccess(ctx, userID, apps[0].ID); err != nil {
			t.Fatalf("revoke access: %v", err)
		}

		favorite, found, err := store.ToggleFavorite(ctx, userID, apps[0].ID)
		if err != nil {
			t.Fatalf("ToggleFavorite: %v", err)
		}
		if found || favorite {
			t.Errorf("ToggleFavorite without access = (%v, %v), want (false, false)", favorite, found)
		}

		ids, err := store.FavoriteIDs(ctx, userID)
		if err != nil {
			t.Fatalf("FavoriteIDs: %v", err)
		}
		if len(ids) != 0 {
			t.Errorf("FavoriteIDs = %v, want empty", ids)
		}
	})

	t.Run("unknown app", func(t *testing.T) {
		t.Parallel()
		store, _, _, userID := newFavoriteFixture(t)

		favorite, found, err := store.ToggleFavorite(ctx, userID, "no-such-app")
		if err != nil {
			t.Fatalf("ToggleFavorite: %v", err)
		}
		if found || favorite {
			t.Errorf("ToggleFavorite for unknown app = (%v, %v), want (false, false)", favorite, found)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		t.Parallel()
		store, _, apps, _ := newFavoriteFixture(t)

		favorite, found, err := store.ToggleFavorite(ctx, "no-such-user", apps[0].ID)
		if err != nil {
			t.Fatalf("ToggleFavorite: %v", err)
		}
		if found || favorite {
			t.Errorf("ToggleFavorite for unknown user = (%v, %v), want (false, false)", favorite, found)
		}
	})
}

// TestStore_FavoriteIDs_PerUser proves a pin is personal: the same app is
// pinned for one user and not for another.
func TestStore_FavoriteIDs_PerUser(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, userStore, apps, firstUserID := newFavoriteFixture(t)

	second := &user.User{Username: "second", Email: "second@example.com", IsActive: true}
	if err := userStore.Create(ctx, second); err != nil {
		t.Fatalf("create second user: %v", err)
	}
	if err := store.GrantAccess(ctx, second.ID, apps[0].ID); err != nil {
		t.Fatalf("grant access: %v", err)
	}

	if _, _, err := store.ToggleFavorite(ctx, firstUserID, apps[0].ID); err != nil {
		t.Fatalf("ToggleFavorite: %v", err)
	}

	first, err := store.FavoriteIDs(ctx, firstUserID)
	if err != nil {
		t.Fatalf("FavoriteIDs (first user): %v", err)
	}
	if !first[apps[0].ID] {
		t.Error("first user's pin missing")
	}

	other, err := store.FavoriteIDs(ctx, second.ID)
	if err != nil {
		t.Fatalf("FavoriteIDs (second user): %v", err)
	}
	if other[apps[0].ID] {
		t.Error("pin leaked to the second user")
	}
}
