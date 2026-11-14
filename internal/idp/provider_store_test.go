package idp_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/idp"
	"github.com/crueber/passage/internal/testutil"
)

// testCipher is a reversible stand-in for the AES-GCM cipher, so tests can
// assert that the stored value is not the plaintext.
type testCipher struct{}

func (testCipher) Encrypt(secret, aad string) (string, error) {
	return "sealed:" + aad + ":" + secret, nil
}

func (testCipher) Decrypt(value, aad string) (string, error) {
	prefix := "sealed:" + aad + ":"
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("bad aad")
	}
	return strings.TrimPrefix(value, prefix), nil
}

func newProviderFixture(t *testing.T) *idp.ProviderStore {
	t.Helper()
	return idp.NewProviderStore(testutil.NewTestDB(t), testCipher{})
}

func TestProviderStore_CRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newProviderFixture(t)

	p := &idp.Provider{
		Name:         "authentik",
		Issuer:       "https://auth.example.com/application/o/passage/",
		ClientID:     "passage",
		ClientSecret: "s3cret",
		Scopes:       idp.DefaultScopes(),
		AutoCreate:   true,
	}
	if err := store.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.ID == "" {
		t.Fatal("Create did not assign an id")
	}
	if p.Label != "authentik" {
		t.Errorf("label = %q, want the name as the default", p.Label)
	}

	got, err := store.Get(ctx, "authentik")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientSecret != "s3cret" || !got.AutoCreate || got.Issuer != p.Issuer {
		t.Errorf("round trip = %+v", got)
	}
	if len(got.Scopes) != 3 || got.Scopes[0] != "openid" {
		t.Errorf("scopes = %v", got.Scopes)
	}

	byID, err := store.GetByID(ctx, p.ID)
	if err != nil || byID.Name != "authentik" {
		t.Fatalf("GetByID = %+v, %v", byID, err)
	}

	list, err := store.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %d, %v", len(list), err)
	}
	if n, err := store.Count(ctx); err != nil || n != 1 {
		t.Fatalf("Count = %d, %v", n, err)
	}

	got.Label = "Authentik"
	got.AutoCreate = false
	got.Scopes = []string{"openid", "email"}
	if err := store.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, err := store.Get(ctx, "authentik")
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if after.Label != "Authentik" || after.AutoCreate || len(after.Scopes) != 2 {
		t.Errorf("after update = %+v", after)
	}

	if err := store.Delete(ctx, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, "authentik"); !errors.Is(err, idp.ErrProviderNotFound) {
		t.Errorf("Get after delete = %v, want ErrProviderNotFound", err)
	}
}

// TestProviderStore_SecretIsSealed proves the row does not hold the plaintext
// and that the cipher is bound to the provider id (a copied row cannot be
// decrypted as another provider).
func TestProviderStore_SecretIsSealed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	store := idp.NewProviderStore(db, testCipher{})

	p := &idp.Provider{Name: "keycloak", Issuer: "https://idp.example.com", ClientID: "passage", ClientSecret: "topsecret"}
	if err := store.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	var stored string
	if err := db.QueryRowContext(ctx, `SELECT client_secret FROM idp_providers WHERE id = ?`, p.ID).Scan(&stored); err != nil {
		t.Fatalf("read raw secret: %v", err)
	}
	if stored == "topsecret" {
		t.Fatal("client secret is stored in plaintext")
	}
	if !strings.HasPrefix(stored, "sealed:"+p.ID+":") {
		t.Errorf("stored secret is not bound to the provider id: %q", stored)
	}

	// An empty secret on update keeps the stored one.
	p.ClientSecret = ""
	p.Label = "Keycloak"
	if err := store.Update(ctx, p); err != nil {
		t.Fatalf("Update with an empty secret: %v", err)
	}
	got, err := store.Get(ctx, "keycloak")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientSecret != "topsecret" {
		t.Errorf("secret after an empty update = %q, want the stored one", got.ClientSecret)
	}
}

func TestProviderStore_DuplicateName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newProviderFixture(t)

	p := &idp.Provider{Name: "authentik", Issuer: "https://a.example.com", ClientID: "x", ClientSecret: "y"}
	if err := store.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}
	dup := &idp.Provider{Name: "authentik", Issuer: "https://b.example.com", ClientID: "x", ClientSecret: "y"}
	if err := store.Create(ctx, dup); err == nil {
		t.Fatal("a duplicate name was accepted")
	}
}

func TestValidateProvider(t *testing.T) {
	t.Parallel()

	valid := func() *idp.Provider {
		return &idp.Provider{
			Name: "authentik", Issuer: "https://auth.example.com/",
			ClientID: "passage", ClientSecret: "x", Scopes: idp.DefaultScopes(),
		}
	}

	tests := []struct {
		name    string
		mutate  func(*idp.Provider)
		wantErr bool
	}{
		{name: "valid", mutate: func(p *idp.Provider) {}},
		{name: "bad slug", mutate: func(p *idp.Provider) { p.Name = "Authentik" }, wantErr: true},
		{name: "http issuer", mutate: func(p *idp.Provider) { p.Issuer = "http://auth.example.com" }, wantErr: true},
		{name: "relative issuer", mutate: func(p *idp.Provider) { p.Issuer = "/auth" }, wantErr: true},
		{name: "issuer with a query", mutate: func(p *idp.Provider) { p.Issuer = "https://a.example.com/?x=1" }, wantErr: true},
		{name: "missing client id", mutate: func(p *idp.Provider) { p.ClientID = "" }, wantErr: true},
		{name: "missing secret", mutate: func(p *idp.Provider) { p.ClientSecret = "" }, wantErr: true},
		{name: "scopes without openid", mutate: func(p *idp.Provider) { p.Scopes = []string{"email"} }, wantErr: true},
		{name: "scope with a space", mutate: func(p *idp.Provider) { p.Scopes = []string{"openid", "a b"} }, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := valid()
			tt.mutate(p)
			err := idp.ValidateProvider(p)
			if tt.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
