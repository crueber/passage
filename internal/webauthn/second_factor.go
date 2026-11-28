package webauthn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/user"
)

// HasCredentials reports whether userID has at least one registered passkey.
// The second-factor page and the begin endpoint use it so the passkey option is
// only offered when it can actually complete a sign-in.
func (h *Handler) HasCredentials(ctx context.Context, userID string) (bool, error) {
	n, err := h.credStore.CountByUser(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("webauthn: count credentials: %w", err)
	}
	return n > 0, nil
}

// BeginSecondFactor starts an assertion ceremony for a user who has already
// proved their password, bound to the pending MFA challenge token bindKey.
//
// The allow-list is the user's own credentials rather than a discoverable
// login, and user verification is required: a second factor must prove the
// person at the authenticator, not merely possession of the device. The session
// data is stored under the challenge token, so the assertion can only complete
// the sign-in it was begun for.
func (h *Handler) BeginSecondFactor(ctx context.Context, u *user.User, bindKey string) ([]byte, error) {
	if bindKey == "" {
		return nil, fmt.Errorf("webauthn: begin second factor: empty challenge binding")
	}
	if !u.IsActive {
		return nil, fmt.Errorf("webauthn: begin second factor: account is inactive")
	}
	if !h.passkeyEnabled(ctx) {
		return nil, fmt.Errorf("webauthn: begin second factor: passkey login is disabled")
	}

	waCreds, err := h.userCredentials(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin second factor: %w", err)
	}
	if len(waCreds) == 0 {
		return nil, fmt.Errorf("webauthn: begin second factor: no credentials for the user")
	}

	options, sessionData, err := h.wa.BeginLogin(
		NewWebAuthnUser(u, waCreds),
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("webauthn: begin second factor assertion: %w", err)
	}

	h.challenges.SetSecondFactor(bindKey, *sessionData)

	body, err := json.Marshal(options)
	if err != nil {
		return nil, fmt.Errorf("webauthn: marshal second factor options: %w", err)
	}
	return body, nil
}

// FinishSecondFactor verifies the assertion in r against the ceremony begun for
// bindKey and returns nil when it is valid.
//
// The ceremony data is single-use: it is popped before verification, so a
// failed or replayed assertion cannot be retried against the same options. The
// library additionally enforces that the asserted credential is on the allow
// list of the user passed here, that a returned user handle equals that user's
// ID, that the signed challenge is the one issued, and that the user-verified
// flag is set. Nothing here creates a session or touches the MFA challenge:
// completing the pending sign-in is the caller's job.
func (h *Handler) FinishSecondFactor(ctx context.Context, r *http.Request, u *user.User, bindKey string) error {
	if bindKey == "" {
		return fmt.Errorf("webauthn: finish second factor: empty challenge binding")
	}
	if !u.IsActive {
		return fmt.Errorf("webauthn: finish second factor: account is inactive")
	}
	if !h.passkeyEnabled(ctx) {
		return fmt.Errorf("webauthn: finish second factor: passkey login is disabled")
	}

	sessionData, err := h.challenges.GetSecondFactor(bindKey)
	if err != nil {
		return fmt.Errorf("webauthn: finish second factor ceremony: %w", err)
	}

	waCreds, err := h.userCredentials(ctx, u.ID)
	if err != nil {
		return fmt.Errorf("webauthn: finish second factor: %w", err)
	}

	credential, err := h.wa.FinishLogin(NewWebAuthnUser(u, waCreds), sessionData, r)
	if err != nil {
		return fmt.Errorf("webauthn: verify second factor assertion: %w", err)
	}

	// Reject potentially cloned authenticators, exactly as passwordless login
	// does: a counter that went backwards is not evidence of the real device.
	if credential.Authenticator.CloneWarning {
		return fmt.Errorf("webauthn: verify second factor assertion: possible cloned authenticator")
	}

	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	if err := h.credStore.UpdateSignCount(ctx, credIDStr, credential.Authenticator.SignCount); err != nil {
		// Non-fatal: the assertion is already verified, and a stale counter only
		// weakens clone detection until the next successful use.
		h.logger.Warn("webauthn: update sign count after second factor", "credential_id", credIDStr, "error", err)
	}
	return nil
}
