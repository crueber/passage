package mfa

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Service is the MFA use-case layer: it combines the pure algorithms with the
// store and an injectable clock. The HTTP layer depends on this type.
type Service struct {
	store  *Store
	issuer string
	now    func() time.Time
}

// NewService wires a Service. issuer is the name authenticator apps show next
// to the account (defaults to "Passage"). now may be nil, in which case the
// wall clock is used; tests inject a fixed clock so TOTP steps are predictable.
func NewService(store *Store, issuer string, now func() time.Time) *Service {
	if issuer == "" {
		issuer = "Passage"
	}
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, issuer: issuer, now: now}
}

// Status describes a user's second-factor state for the Security page.
type Status struct {
	// Enabled is true once a TOTP code has been verified.
	Enabled bool
	// EnabledAt is when enrollment completed (zero when not enabled).
	EnabledAt time.Time
	// RemainingCodes counts unused recovery codes.
	RemainingCodes int
}

// Enrollment is a pending secret, ready to be shown once. Secret is the raw
// base32 value used by the otpauth URI; Display is the same value grouped in
// fours for manual entry.
type Enrollment struct {
	Secret  string
	Display string
	URI     string
}

// Status returns the user's MFA state. A user with no MFA row, or one with only
// a pending enrollment, is reported as not enabled.
func (s *Service) Status(ctx context.Context, userID string) (Status, error) {
	c, err := s.store.Get(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Status{}, nil
		}
		return Status{}, fmt.Errorf("mfa status: %w", err)
	}
	var st Status
	if c.EnabledAt != nil {
		st.Enabled = true
		st.EnabledAt = *c.EnabledAt
		st.RemainingCodes, err = s.store.RemainingRecoveryCodes(ctx, userID)
		if err != nil {
			return Status{}, fmt.Errorf("mfa status: %w", err)
		}
	}
	return st, nil
}

// Enabled reports whether the user must present a second factor at login.
func (s *Service) Enabled(ctx context.Context, userID string) (bool, error) {
	ok, err := s.store.Enabled(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("mfa enabled: %w", err)
	}
	return ok, nil
}

// BeginEnrollment issues a fresh pending secret. Re-visiting the setup page
// rotates the secret (the previously displayed one stops working), which is
// what a user who never completed enrollment expects.
func (s *Service) BeginEnrollment(ctx context.Context, userID, account string) (Enrollment, error) {
	secret, err := GenerateSecret()
	if err != nil {
		return Enrollment{}, err
	}
	if err := s.store.UpsertPending(ctx, userID, secret, s.now().UTC()); err != nil {
		return Enrollment{}, fmt.Errorf("mfa begin enrollment: %w", err)
	}
	return s.enrollmentFor(account, secret), nil
}

// PendingEnrollment re-reads the current pending secret, so a failed
// verification can re-render the same page without rotating it.
func (s *Service) PendingEnrollment(ctx context.Context, userID, account string) (Enrollment, error) {
	c, err := s.store.Get(ctx, userID)
	if err != nil {
		return Enrollment{}, fmt.Errorf("mfa pending enrollment: %w", err)
	}
	if c.EnabledAt != nil {
		return Enrollment{}, ErrNotPending
	}
	return s.enrollmentFor(account, c.Secret), nil
}

// ConfirmEnrollment verifies the first code against the pending secret and, on
// success, enables the factor and returns the plaintext recovery codes. That is
// the only moment the codes exist in plaintext.
func (s *Service) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	c, err := s.store.Get(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa confirm enrollment: %w", err)
	}
	if c.EnabledAt != nil {
		return nil, ErrNotPending
	}

	step, ok := Validate(c.Secret, code, s.now(), c.LastStep)
	if !ok {
		return nil, ErrInvalidCode
	}

	codes, err := GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		return nil, fmt.Errorf("mfa confirm enrollment: %w", err)
	}
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hashes[i] = HashRecoveryCode(code)
	}

	now := s.now().UTC()
	if err := s.store.EnableWithRecoveryCodes(ctx, userID, step, hashes, now); err != nil {
		return nil, fmt.Errorf("mfa confirm enrollment: %w", err)
	}
	return codes, nil
}

// Verify checks a submitted code — TOTP or recovery — and returns the method
// that matched ("totp" or "recovery") for the audit log.
//
// TOTP is accepted only for a step above the stored watermark and the watermark
// is written with a WHERE guard; recovery codes are claimed with an UPDATE that
// only succeeds on an unused row. Both are therefore single-use under
// concurrent requests.
func (s *Service) Verify(ctx context.Context, userID, code string) (string, error) {
	c, err := s.store.Get(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return "", ErrNotEnabled
		}
		return "", fmt.Errorf("mfa verify: %w", err)
	}
	if c.EnabledAt == nil {
		return "", ErrNotEnabled
	}
	now := s.now().UTC()

	if LooksLikeTOTP(code) {
		step, ok := Validate(c.Secret, code, now, c.LastStep)
		if !ok {
			return "", ErrInvalidCode
		}
		accepted, err := s.store.AcceptStep(ctx, userID, step, now)
		if err != nil {
			return "", fmt.Errorf("mfa verify accept step: %w", err)
		}
		if !accepted {
			return "", ErrReplay
		}
		return "totp", nil
	}

	normalized := NormalizeRecoveryCode(code)
	if len(normalized) != recoveryCodeChars {
		return "", ErrInvalidCode
	}
	used, err := s.store.ConsumeRecoveryCode(ctx, userID, HashRecoveryCode(code), now)
	if err != nil {
		return "", fmt.Errorf("mfa verify recovery code: %w", err)
	}
	if !used {
		return "", ErrInvalidCode
	}
	return "recovery", nil
}

// Disable removes the user's second factor. The caller is responsible for
// re-authenticating with the current password first.
func (s *Service) Disable(ctx context.Context, userID string) error {
	if err := s.store.Delete(ctx, userID); err != nil {
		return fmt.Errorf("mfa disable: %w", err)
	}
	return nil
}

// Reset removes another user's second factor (admin recovery path). It is
// identical to Disable at this layer; kept as a named method so the intent is
// readable at the call site and auditable.
func (s *Service) Reset(ctx context.Context, userID string) error {
	if err := s.store.Delete(ctx, userID); err != nil {
		return fmt.Errorf("mfa reset: %w", err)
	}
	return nil
}

// RegenerateRecoveryCodes replaces the recovery-code set for an enabled
// credential and returns the new plaintext codes. Old codes stop working
// immediately.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	enabled, err := s.store.Enabled(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("mfa regenerate codes: %w", err)
	}
	if !enabled {
		return nil, ErrNotEnabled
	}

	codes, err := GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		return nil, fmt.Errorf("mfa regenerate codes: %w", err)
	}
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hashes[i] = HashRecoveryCode(code)
	}
	if err := s.store.ReplaceRecoveryCodes(ctx, userID, hashes, s.now().UTC()); err != nil {
		return nil, fmt.Errorf("mfa regenerate codes: %w", err)
	}
	return codes, nil
}

// CreateChallenge stores a pending second factor for userID and returns the
// token for the cookie. The token is 32 bytes of crypto/rand, hex encoded,
// bound to one user, one return target, and a five-minute expiry.
func (s *Service) CreateChallenge(ctx context.Context, userID, returnTo string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mfa create challenge: %w", err)
	}
	token := hex.EncodeToString(b)
	now := s.now().UTC()
	if err := s.store.CreateChallenge(ctx, token, userID, returnTo, now.Add(ChallengeTTL), now); err != nil {
		return "", fmt.Errorf("mfa create challenge: %w", err)
	}
	return token, nil
}

// Challenge returns the live challenge for token. An expired challenge is
// rejected (and left for the sweeper to delete).
func (s *Service) Challenge(ctx context.Context, token string) (*Challenge, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	c, err := s.store.GetChallenge(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("mfa challenge: %w", err)
	}
	if !c.ExpiresAt.After(s.now().UTC()) {
		return nil, ErrChallengeExpired
	}
	return c, nil
}

// ConsumeChallenge deletes a challenge. The caller treats a delete failure as
// fatal so a completed challenge can never be replayed into a second session.
func (s *Service) ConsumeChallenge(ctx context.Context, token string) error {
	if err := s.store.DeleteChallenge(ctx, token); err != nil {
		return fmt.Errorf("mfa consume challenge: %w", err)
	}
	return nil
}

// DeleteExpiredChallenges is the periodic sweeper.
func (s *Service) DeleteExpiredChallenges(ctx context.Context) error {
	if err := s.store.DeleteExpiredChallenges(ctx, s.now().UTC()); err != nil {
		return fmt.Errorf("mfa delete expired challenges: %w", err)
	}
	return nil
}

// ListEnabledIDs backs the admin user-list badge.
func (s *Service) ListEnabledIDs(ctx context.Context) ([]string, error) {
	ids, err := s.store.ListEnabledIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("mfa list enabled: %w", err)
	}
	return ids, nil
}

// enrollmentFor builds the display form of a secret: the raw base32 value for
// the URI, and the same value with spacing for manual entry.
func (s *Service) enrollmentFor(account, secret string) Enrollment {
	return Enrollment{
		Secret:  secret,
		Display: FormatSecret(strings.ToUpper(secret)),
		URI:     ProvisioningURI(s.issuer, account, secret),
	}
}
