package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/config"
)

func validProvider() config.ProviderConfig {
	return config.ProviderConfig{
		Name:         "authentik",
		Label:        "Authentik",
		Issuer:       "https://auth.example.com/application/o/passage",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AutoCreate:   false,
	}
}

// TestValidate_Providers is table-driven: every case starts from a valid
// provider list and mutates one thing, so the expected error is unambiguous.
func TestValidate_Providers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{
			name:   "valid provider",
			mutate: func(*config.Config) {},
		},
		{
			name: "https issuer with path and trailing slash",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].Issuer = "https://auth.example.com/application/o/passage/"
			},
		},
		{
			name: "invalid slug",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].Name = "Not A Slug"
			},
			wantErr: "must be a lowercase slug",
		},
		{
			name: "duplicate name",
			mutate: func(c *config.Config) {
				second := validProvider()
				c.Auth.Providers = append(c.Auth.Providers, second)
			},
			wantErr: "duplicated",
		},
		{
			name: "http issuer",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].Issuer = "http://auth.example.com"
			},
			wantErr: "must use https",
		},
		{
			name: "issuer without host",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].Issuer = "https:///path"
			},
			wantErr: "must include a host",
		},
		{
			name: "issuer with query",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].Issuer = "https://auth.example.com?x=1"
			},
			wantErr: "must not include a query",
		},
		{
			name: "missing client id",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].ClientID = ""
			},
			wantErr: "client_id must not be empty",
		},
		{
			name: "missing client secret",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].ClientSecret = ""
			},
			wantErr: "client_secret must not be empty",
		},
		{
			name: "scopes without openid",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].Scopes = []string{"email", "profile"}
			},
			wantErr: "must include \"openid\"",
		},
		{
			name: "scope with a space",
			mutate: func(c *config.Config) {
				c.Auth.Providers[0].Scopes = []string{"openid", "email profile"}
			},
			wantErr: "invalid scope",
		},
		{
			name: "providers require base_url",
			mutate: func(c *config.Config) {
				c.Server.BaseURL = ""
			},
			wantErr: "server.base_url is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.Load("")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			cfg.Server.BaseURL = "https://auth.example.com"
			cfg.Auth.Providers = []config.ProviderConfig{validProvider()}
			tt.mutate(cfg)

			err = cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate: expected an error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate error = %v; want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestLoad_ProvidersFromYAML pins the documented YAML shape.
func TestLoad_ProvidersFromYAML(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "passage.yaml")
	yaml := `
server:
  base_url: "https://auth.example.com"
auth:
  providers:
    - name: "authentik"
      label: "Authentik"
      issuer: "https://id.example.com/application/o/passage/"
      client_id: "passage"
      client_secret: "s3cret"
      scopes: ["openid", "email", "profile"]
      auto_create: true
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(cfg.Auth.Providers) != 1 {
		t.Fatalf("got %d providers; want 1", len(cfg.Auth.Providers))
	}
	p := cfg.Auth.Providers[0]
	if p.Name != "authentik" || p.Label != "Authentik" || !p.AutoCreate {
		t.Errorf("provider = %+v; want authentik/Authentik/auto_create", p)
	}
	if p.ClientSecret != "s3cret" {
		t.Errorf("client_secret not parsed")
	}
}
