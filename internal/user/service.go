package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/crueber/passage/internal/config"
	"github.com/crueber/passage/internal/settings"
	"github.com/crueber/passage/internal/theme"
)

// SessionRevoker invalidates all sessions for a user. Implemented by the
// session service; defined here at the consumer boundary because the session
// package imports this one (a user-side import would cycle).
type SessionRevoker interface {
	RevokeAllByUser(ctx context.Context, userID string) error
}

// Service implements business logic for user management.
type Service struct {
	store      Store
	tokenStore TokenStore
	sessions   SessionRevoker
	cfg        *config.Config
	// settings supplies live feature settings (password-hashing cost, SMTP
	// availability). May be nil in tests, in which case cfg is the fallback.
	settings settingsReader
}

// NewService creates a new Service with the given dependencies. sessions may
// be nil (used by tests); when set, password changes revoke all of the user's
// sessions per OWASP session-management guidance.
func NewService(store Store, tokenStore TokenStore, sessions SessionRevoker, cfg *config.Config) *Service {
	return &Service{
		store:      store,
		tokenStore: tokenStore,
		sessions:   sessions,
		cfg:        cfg,
	}
}

// SetSettings wires the live settings store. It is optional: without it the
// config snapshot remains authoritative, which is what tests rely on.
func (s *Service) SetSettings(store settingsReader) { s.settings = store }

// bcryptCost returns the current hashing cost. Reading it per hash makes a
// cost change in the admin UI apply immediately instead of at the next start.
func (s *Service) bcryptCost(ctx context.Context) int {
	return settings.Int(ctx, s.settings, settings.BcryptCost, s.cfg.Auth.BcryptCost, 10, 31)
}

// Register creates a new user account. It checks that registration is enabled,
// validates inputs, hashes the password with bcrypt, and persists the user.
func (s *Service) Register(ctx context.Context, username, email, password string) (*User, error) {
	if !s.cfg.Auth.AllowRegistration {
		return nil, ErrRegistrationDisabled
	}

	if username == "" {
		return nil, ErrUsernameRequired
	}
	if email == "" {
		return nil, ErrEmailRequired
	}
	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost(ctx))
	if err != nil {
		return nil, fmt.Errorf("register hash password: %w", err)
	}

	u := &User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		IsActive:     true,
		IsAdmin:      false,
		Roles:        "[]",
		// Without a usable SMTP server there is no way to prove control of the
		// address, so the account is created verified rather than nagging the
		// user with a banner they cannot clear.
		EmailVerified: !s.smtpConfigured(ctx),
	}

	if err := s.store.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("register create user: %w", err)
	}
	return u, nil
}

// CreateAdmin creates a new admin user account, bypassing the allow_registration
// setting. It is used only during the initial /setup flow to create the first
// admin when no admin yet exists.
func (s *Service) CreateAdmin(ctx context.Context, username, email, password string) (*User, error) {
	if username == "" {
		return nil, ErrUsernameRequired
	}
	if email == "" {
		return nil, ErrEmailRequired
	}
	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost(ctx))
	if err != nil {
		return nil, fmt.Errorf("create admin hash password: %w", err)
	}

	u := &User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hash),
		IsActive:     true,
		IsAdmin:      true,
		Roles:        "[]",
		// The operator creates the bootstrap admin out of band; there is no
		// self-service owner to verify against, so treat it as trusted.
		EmailVerified: true,
	}

	if err := s.store.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("create admin create user: %w", err)
	}
	return u, nil
}

// Authenticate verifies credentials and returns the user if valid.
// Returns ErrInvalidCredentials if the username does not exist or the password
// is wrong. Returns ErrUserInactive if the account has been disabled.
func (s *Service) Authenticate(ctx context.Context, username, password string) (*User, error) {
	u, err := s.store.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Hash a dummy value to maintain constant-time behavior and
			// prevent user enumeration via timing side-channels.
			_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummyhashfortimingnnn.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), []byte(password))
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if !u.IsActive {
		return nil, ErrUserInactive
	}

	return u, nil
}

// GetByID returns the user with the given ID.
func (s *Service) GetByID(ctx context.Context, id string) (*User, error) {
	u, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("user: get by id: %w", err)
	}
	return u, nil
}

// GetByEmail returns the user with the given email address. The address is
// normalized to lowercase, matching how registration and magic-link accounts
// store it.
func (s *Service) GetByEmail(ctx context.Context, emailAddr string) (*User, error) {
	u, err := s.store.GetByEmail(ctx, strings.ToLower(strings.TrimSpace(emailAddr)))
	if err != nil {
		return nil, fmt.Errorf("user: get by email: %w", err)
	}
	return u, nil
}

// CreateExternalUser creates an account for an upstream identity provider. It
// has no password by design: the provider is the credential. EmailVerified is
// copied from the provider's email_verified claim, and Name from its name
// claim when present.
//
// The caller is responsible for the policy gate (provider auto_create plus the
// global registration setting) and for creating the idp_links row. A username
// collision is resolved with a random suffix rather than failing the sign-in;
// an email collision is returned as ErrEmailTaken so the caller can refuse
// instead of silently attaching a second account to one address.
func (s *Service) CreateExternalUser(ctx context.Context, username, emailAddr, name string, emailVerified bool) (*User, error) {
	normalized := strings.ToLower(strings.TrimSpace(emailAddr))
	if normalized == "" {
		return nil, ErrEmailRequired
	}

	base := deriveUsername(username, normalized)

	u := &User{
		Username:      base,
		Email:         normalized,
		Name:          name,
		IsActive:      true,
		Roles:         "[]",
		EmailVerified: emailVerified,
	}

	if err := s.store.Create(ctx, u); err != nil {
		if !errors.Is(err, ErrUsernameTaken) {
			return nil, fmt.Errorf("create external user: %w", err)
		}
		suffix, randErr := randomHex(2)
		if randErr != nil {
			return nil, fmt.Errorf("create external user: generate suffix: %w", randErr)
		}
		u.ID = ""
		u.Username = base + "_" + suffix
		if err := s.store.Create(ctx, u); err != nil {
			return nil, fmt.Errorf("create external user with suffix: %w", err)
		}
	}
	return u, nil
}

// deriveUsername turns a preferred username (or the email local part) into a
// safe, non-empty local username no longer than 64 characters.
func deriveUsername(preferred, emailAddr string) string {
	candidate := preferred
	if candidate == "" {
		candidate = emailAddr
		if idx := strings.Index(candidate, "@"); idx >= 0 {
			candidate = candidate[:idx]
		}
	}
	derived := nonAlphanumRe.ReplaceAllString(candidate, "_")
	if len(derived) > 64 {
		derived = derived[:64]
	}
	if derived == "" {
		derived = "user"
	}
	return derived
}

// GeneratePasswordReset looks up the user by email and creates a reset token.
// If the email is not found, nil is returned for both values to avoid email
// enumeration.
func (s *Service) GeneratePasswordReset(ctx context.Context, email string) (token string, err error) {
	u, err := s.store.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Do not reveal whether the email exists.
			return "", nil
		}
		return "", fmt.Errorf("generate password reset: %w", err)
	}

	token, err = s.tokenStore.CreateResetToken(ctx, u.ID)
	if err != nil {
		return "", fmt.Errorf("generate password reset create token: %w", err)
	}
	return token, nil
}

// ResetPassword validates the token and sets the user's password to newPassword.
func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	rt, err := s.tokenStore.GetResetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("reset password get token: %w", err)
	}

	if rt.UsedAt != nil {
		return ErrTokenUsed
	}

	if rt.ExpiresAt.Before(time.Now().UTC()) {
		return ErrTokenExpired
	}

	if err := s.ChangePassword(ctx, rt.UserID, newPassword); err != nil {
		return fmt.Errorf("reset password change: %w", err)
	}

	if err := s.tokenStore.MarkResetTokenUsed(ctx, token); err != nil {
		return fmt.Errorf("reset password mark token used: %w", err)
	}
	return nil
}

// ChangePassword sets a new bcrypt-hashed password for the given user.
func (s *Service) ChangePassword(ctx context.Context, userID, newPassword string) error {
	if len(newPassword) < 8 {
		return ErrPasswordTooShort
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.bcryptCost(ctx))
	if err != nil {
		return fmt.Errorf("change password hash: %w", err)
	}

	u, err := s.store.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("change password get user: %w", err)
	}

	u.PasswordHash = string(hash)
	if err := s.store.Update(ctx, u); err != nil {
		return fmt.Errorf("change password update user: %w", err)
	}

	// Invalidate all of the user's sessions: a stolen session must not survive
	// a password rotation (OWASP session management — invalidate on password
	// change). Runs after the hash is persisted so a failed revocation is
	// visible to the caller rather than silently skipped.
	if s.sessions != nil {
		if err := s.sessions.RevokeAllByUser(ctx, userID); err != nil {
			return fmt.Errorf("change password revoke sessions: %w", err)
		}
	}
	return nil
}

// nonAlphanumRe matches any character that is not a letter, digit, dash, or underscore.
var nonAlphanumRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// FindOrCreateByEmail looks up a user by email address, creating one if none
// exists. The second return value is true when a new user was created.
func (s *Service) FindOrCreateByEmail(ctx context.Context, emailAddr string) (*User, bool, error) {
	normalized := strings.ToLower(strings.TrimSpace(emailAddr))

	u, err := s.store.GetByEmail(ctx, normalized)
	if err == nil {
		return u, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, fmt.Errorf("find or create by email: %w", err)
	}

	// Derive a username from the local part of the email address.
	localPart := normalized
	if idx := strings.Index(normalized, "@"); idx >= 0 {
		localPart = normalized[:idx]
	}
	derived := nonAlphanumRe.ReplaceAllString(localPart, "_")
	if len(derived) > 64 {
		derived = derived[:64]
	}
	if derived == "" {
		derived = "user"
	}

	newUser := &User{
		Username: derived,
		Email:    normalized,
		IsActive: true,
		Roles:    "[]",
		// A magic-link account starts unverified; it is flipped to verified when
		// the link is actually used, which is the proof of mailbox control.
		EmailVerified: false,
	}

	if err := s.store.Create(ctx, newUser); err != nil {
		if errors.Is(err, ErrUsernameTaken) {
			// Append a 4-char random hex suffix and retry once.
			suffix, randErr := randomHex(2) // 2 bytes = 4 hex chars
			if randErr != nil {
				return nil, false, fmt.Errorf("find or create by email: generate suffix: %w", randErr)
			}
			newUser.ID = "" // reset so Create assigns a fresh UUID
			newUser.Username = derived + "_" + suffix
			if err2 := s.store.Create(ctx, newUser); err2 != nil {
				if errors.Is(err2, ErrEmailTaken) {
					// Race condition: another goroutine created the user — re-fetch.
					existing, fetchErr := s.store.GetByEmail(ctx, normalized)
					if fetchErr != nil {
						return nil, false, fmt.Errorf("find or create by email: re-fetch after race: %w", fetchErr)
					}
					return existing, false, nil
				}
				return nil, false, fmt.Errorf("find or create by email: create with suffix: %w", err2)
			}
			return newUser, true, nil
		}
		if errors.Is(err, ErrEmailTaken) {
			// Race condition: another goroutine created the user — re-fetch.
			existing, fetchErr := s.store.GetByEmail(ctx, normalized)
			if fetchErr != nil {
				return nil, false, fmt.Errorf("find or create by email: re-fetch after email race: %w", fetchErr)
			}
			return existing, false, nil
		}
		return nil, false, fmt.Errorf("find or create by email: create: %w", err)
	}
	return newUser, true, nil
}

// randomHex generates n random bytes and returns them as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateMagicLinkToken creates a new magic link token for the given user.
func (s *Service) CreateMagicLinkToken(ctx context.Context, userID string, ttlMinutes int) (*MagicLinkToken, error) {
	tok, err := s.tokenStore.CreateMagicLinkToken(ctx, userID, ttlMinutes)
	if err != nil {
		return nil, fmt.Errorf("user: create magic link token: %w", err)
	}
	return tok, nil
}

// ConsumeMagicLinkToken validates a magic link token and returns the associated
// user. The token is marked used atomically to prevent double-spend.
func (s *Service) ConsumeMagicLinkToken(ctx context.Context, token string) (*User, error) {
	t, err := s.tokenStore.GetMagicLinkToken(ctx, token)
	if err != nil {
		if errors.Is(err, ErrMagicLinkTokenNotFound) {
			return nil, ErrMagicLinkTokenNotFound
		}
		return nil, fmt.Errorf("user: consume magic link token get: %w", err)
	}

	if t.ExpiresAt.Before(time.Now()) {
		return nil, ErrMagicLinkTokenExpired
	}
	if t.UsedAt != nil {
		return nil, ErrMagicLinkTokenUsed
	}

	if err := s.tokenStore.MarkMagicLinkTokenUsed(ctx, token); err != nil {
		if errors.Is(err, ErrMagicLinkTokenUsed) {
			return nil, ErrMagicLinkTokenUsed
		}
		return nil, fmt.Errorf("user: consume magic link token mark used: %w", err)
	}

	u, err := s.store.GetByID(ctx, t.UserID)
	if err != nil {
		return nil, fmt.Errorf("user: consume magic link token get user: %w", err)
	}
	return u, nil
}

// DeleteExpiredMagicLinkTokens removes expired and used magic link tokens.
func (s *Service) DeleteExpiredMagicLinkTokens(ctx context.Context) error {
	if err := s.tokenStore.DeleteExpiredMagicLinkTokens(ctx); err != nil {
		return fmt.Errorf("user: delete expired magic link tokens: %w", err)
	}
	return nil
}

// EmailVerificationTTL is how long an email verification link stays valid.
const EmailVerificationTTL = 24 * time.Hour

// smtpConfigured reports whether outgoing mail is usable. A host without a
// From address cannot send (go-mail rejects the From header), so both are
// required. When false, registrations are auto-verified and no verification
// link is ever generated. Read from live settings so configuring mail does not
// need a restart.
func (s *Service) smtpConfigured(ctx context.Context) bool {
	host := s.cfg.SMTP.Host
	from := s.cfg.SMTP.From
	if s.settings != nil {
		host = settings.String(ctx, s.settings, settings.SMTPHost, host)
		from = settings.String(ctx, s.settings, settings.SMTPFrom, from)
	}
	return host != "" && from != ""
}

// CreateEmailVerificationToken issues a fresh verification token for the user,
// replacing any earlier unused one.
func (s *Service) CreateEmailVerificationToken(ctx context.Context, userID, emailAddr string) (*EmailVerificationToken, error) {
	tok, err := s.tokenStore.CreateEmailVerificationToken(ctx, userID, emailAddr, EmailVerificationTTL)
	if err != nil {
		return nil, fmt.Errorf("user: create email verification token: %w", err)
	}
	return tok, nil
}

// ConsumeEmailVerificationToken validates a single-use verification token and
// marks the account's email verified. The token is consumed atomically after
// the address is confirmed to still match, so a replayed link, or a link for an
// address that has since changed, cannot verify an account.
func (s *Service) ConsumeEmailVerificationToken(ctx context.Context, token string) (*User, error) {
	t, err := s.tokenStore.GetEmailVerificationToken(ctx, token)
	if err != nil {
		if errors.Is(err, ErrEmailVerificationTokenNotFound) {
			return nil, ErrEmailVerificationTokenNotFound
		}
		return nil, fmt.Errorf("user: consume email verification token get: %w", err)
	}

	if t.ExpiresAt.Before(time.Now().UTC()) {
		return nil, ErrEmailVerificationTokenExpired
	}
	if t.UsedAt != nil {
		return nil, ErrEmailVerificationTokenUsed
	}

	u, err := s.store.GetByID(ctx, t.UserID)
	if err != nil {
		return nil, fmt.Errorf("user: consume email verification token get user: %w", err)
	}
	// The token proves control of the address it was mailed to. If the account's
	// address has changed since (e.g. an admin edit), the link is stale and must
	// not verify the new address.
	if t.Email != "" && !strings.EqualFold(t.Email, u.Email) {
		return nil, ErrEmailVerificationTokenNotFound
	}

	if err := s.tokenStore.MarkEmailVerificationTokenUsed(ctx, token); err != nil {
		if errors.Is(err, ErrEmailVerificationTokenUsed) {
			return nil, ErrEmailVerificationTokenUsed
		}
		return nil, fmt.Errorf("user: consume email verification token mark used: %w", err)
	}

	if err := s.store.SetEmailVerified(ctx, t.UserID, true); err != nil {
		return nil, fmt.Errorf("user: consume email verification token set verified: %w", err)
	}

	u.EmailVerified = true
	return u, nil
}

// MarkEmailVerified records that the account holder has proven control of their
// address. Used after a successful magic-link sign-in.
func (s *Service) MarkEmailVerified(ctx context.Context, userID string) error {
	if err := s.store.SetEmailVerified(ctx, userID, true); err != nil {
		return fmt.Errorf("user: mark email verified: %w", err)
	}
	return nil
}

// InvitationTTLDefault is how long an invitation link stays valid when the
// admin form does not say otherwise.
const InvitationTTLDefault = 7 * 24 * time.Hour

// MaxDisplayNameLength bounds the free-text display name. It is long enough
// for any real name and short enough that it cannot be used to break a layout.
const MaxDisplayNameLength = 100

// UpdateTheme sets the account's colour-theme override. Empty means "follow
// the server default"; any other value must be a registered theme slug, so a
// stray form value cannot produce an unthemed page.
func (s *Service) UpdateTheme(ctx context.Context, userID, themeName string) error {
	themeName = strings.TrimSpace(themeName)
	if themeName != "" {
		if _, ok := theme.Lookup(themeName); !ok {
			return ErrInvalidTheme
		}
	}
	if err := s.store.SetTheme(ctx, userID, themeName); err != nil {
		return fmt.Errorf("user: update theme: %w", err)
	}
	return nil
}

// UpdateDisplayName sets the account's display name. The value is trimmed and
// may be empty, which the UI renders as "no display name". Only the name
// column is written, so a concurrent admin edit to other fields survives.
func (s *Service) UpdateDisplayName(ctx context.Context, userID, name string) error {
	name = strings.TrimSpace(name)
	if len(name) > MaxDisplayNameLength {
		return ErrNameTooLong
	}
	if err := s.store.SetName(ctx, userID, name); err != nil {
		return fmt.Errorf("user: update display name: %w", err)
	}
	return nil
}

// CreateInvitation records a pending invitation and returns it. Nothing is
// written to users: the account springs into existence only when the recipient
// accepts. An address that already has an account is refused, because the
// invite link creates a new account rather than signing an existing one in.
func (s *Service) CreateInvitation(ctx context.Context, emailAddr, name, invitedBy string, ttl time.Duration) (*Invitation, error) {
	normalized := strings.ToLower(strings.TrimSpace(emailAddr))
	if normalized == "" || !strings.Contains(normalized, "@") {
		return nil, ErrEmailRequired
	}
	if !s.smtpConfigured(ctx) {
		// The whole feature is email; without a usable sender the link could
		// never reach anyone.
		return nil, ErrSMTPNotConfigured
	}

	if _, err := s.store.GetByEmail(ctx, normalized); err == nil {
		return nil, ErrEmailTaken
	} else if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("create invitation check email: %w", err)
	}

	inv, err := s.tokenStore.CreateInvitation(ctx, normalized, strings.TrimSpace(name), invitedBy, ttl)
	if err != nil {
		return nil, fmt.Errorf("user: create invitation: %w", err)
	}
	return inv, nil
}

// GetPendingInvitation returns an invitation that can still be accepted, or a
// typed error describing why it cannot (missing, expired, already accepted).
func (s *Service) GetPendingInvitation(ctx context.Context, token string) (*Invitation, error) {
	inv, err := s.tokenStore.GetInvitation(ctx, token)
	if err != nil {
		if errors.Is(err, ErrInvitationNotFound) {
			return nil, ErrInvitationNotFound
		}
		return nil, fmt.Errorf("user: get invitation: %w", err)
	}
	if inv.AcceptedAt != nil {
		return nil, ErrInvitationAccepted
	}
	if !inv.Pending() {
		return nil, ErrInvitationExpired
	}
	return inv, nil
}

// AcceptInvitation creates the user described by an invitation, consuming it.
// The address comes from the invitation (the recipient cannot change it); the
// recipient chooses a username, display name and password. Using the link
// proves control of the mailbox, so the new account starts verified.
//
// The invitation is marked accepted only after the user row is written: if
// username validation fails, the link stays usable. The email uniqueness
// constraint closes the concurrent-accept race.
func (s *Service) AcceptInvitation(ctx context.Context, token, username, displayName, password string) (*User, error) {
	inv, err := s.GetPendingInvitation(ctx, token)
	if err != nil {
		return nil, err
	}

	username = strings.TrimSpace(username)
	displayName = strings.TrimSpace(displayName)
	if username == "" {
		return nil, ErrUsernameRequired
	}
	if len(displayName) > MaxDisplayNameLength {
		return nil, ErrNameTooLong
	}
	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}

	if _, err := s.store.GetByEmail(ctx, inv.Email); err == nil {
		return nil, ErrEmailTaken
	} else if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("accept invitation check email: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost(ctx))
	if err != nil {
		return nil, fmt.Errorf("accept invitation hash password: %w", err)
	}

	u := &User{
		Username:     username,
		Email:        inv.Email,
		Name:         displayName,
		PasswordHash: string(hash),
		IsActive:     true,
		Roles:        "[]",
		// Clicking the emailed link proves control of the mailbox.
		EmailVerified: true,
	}

	if err := s.store.Create(ctx, u); err != nil {
		return nil, fmt.Errorf("accept invitation create user: %w", err)
	}

	if err := s.tokenStore.MarkInvitationAccepted(ctx, token); err != nil {
		if errors.Is(err, ErrInvitationAccepted) {
			// Another request consumed the invitation first. Roll back the
			// account this call just created so the two cannot both win.
			if delErr := s.store.Delete(ctx, u.ID); delErr != nil {
				return nil, fmt.Errorf("accept invitation roll back user: %w", errors.Join(err, delErr))
			}
			return nil, ErrInvitationAccepted
		}
		return nil, fmt.Errorf("accept invitation mark accepted: %w", err)
	}

	return u, nil
}

// ListPendingInvitations returns the invitations an administrator can still
// revoke or that are still waiting on a recipient.
func (s *Service) ListPendingInvitations(ctx context.Context) ([]*Invitation, error) {
	invitations, err := s.tokenStore.ListPendingInvitations(ctx)
	if err != nil {
		return nil, fmt.Errorf("user: list pending invitations: %w", err)
	}
	return invitations, nil
}

// RevokeInvitation deletes one pending invitation, invalidating its link.
func (s *Service) RevokeInvitation(ctx context.Context, id string) error {
	if err := s.tokenStore.DeleteInvitation(ctx, id); err != nil {
		return fmt.Errorf("user: revoke invitation: %w", err)
	}
	return nil
}

// DeleteExpiredInvitations removes expired, never-accepted invitations.
func (s *Service) DeleteExpiredInvitations(ctx context.Context) error {
	if err := s.tokenStore.DeleteExpiredInvitations(ctx); err != nil {
		return fmt.Errorf("user: delete expired invitations: %w", err)
	}
	return nil
}
