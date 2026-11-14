package adminapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Service owns the token lifecycle: creation, listing, revocation, and bearer
// authentication. The plaintext token never leaves Create.
type Service struct {
	store  Store
	logger *slog.Logger
}

// NewService creates a Service backed by the given store.
func NewService(store Store, logger *slog.Logger) *Service {
	return &Service{store: store, logger: logger}
}

// Create mints a new token. It returns the plaintext token, which the caller
// must show once and never store; only the hash is persisted.
func (s *Service) Create(ctx context.Context, name string) (string, *Token, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, ErrNameRequired
	}

	plaintext, hash, err := GenerateToken()
	if err != nil {
		return "", nil, fmt.Errorf("create api token: %w", err)
	}

	t := &Token{Name: name, TokenHash: hash}
	if err := s.store.Create(ctx, t); err != nil {
		return "", nil, fmt.Errorf("create api token: %w", err)
	}
	return plaintext, t, nil
}

// List returns every token, newest first, revoked ones included.
func (s *Service) List(ctx context.Context) ([]*Token, error) {
	tokens, err := s.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	return tokens, nil
}

// Revoke invalidates a token and returns it. Revoking an already-revoked token
// is a no-op that still returns the token, so the admin UI stays idempotent.
func (s *Service) Revoke(ctx context.Context, id string) (*Token, error) {
	t, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("revoke api token: %w", err)
	}
	if t.Revoked() {
		return t, nil
	}

	now := time.Now().UTC()
	if err := s.store.Revoke(ctx, id, now); err != nil {
		return nil, fmt.Errorf("revoke api token: %w", err)
	}
	t.RevokedAt = now
	return t, nil
}

// Authenticate validates a presented bearer token. Unknown, malformed, and
// revoked tokens all return ErrTokenNotFound so a caller cannot tell them
// apart. On success last_used_at is updated best-effort: a failed write is
// logged and never fails the request.
func (s *Service) Authenticate(ctx context.Context, presented string) (*Token, error) {
	if !strings.HasPrefix(presented, TokenPrefix) {
		return nil, ErrTokenNotFound
	}

	t, err := s.store.GetByHash(ctx, HashToken(presented))
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("authenticate api token: %w", err)
	}
	if t.Revoked() {
		return nil, ErrTokenNotFound
	}

	now := time.Now().UTC()
	if err := s.store.TouchLastUsed(ctx, t.ID, now); err != nil {
		s.logger.Warn("adminapi: update token last_used_at", "token_id", t.ID, "error", err)
	} else {
		t.LastUsedAt = now
	}
	return t, nil
}
