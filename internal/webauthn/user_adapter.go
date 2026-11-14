package webauthn

import (
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/user"
)

// WebAuthnUser adapts our user.User to satisfy the go-webauthn webauthn.User interface.
type WebAuthnUser struct {
	user        *user.User
	credentials []gowebauthn.Credential
}

// NewWebAuthnUser creates a WebAuthnUser with pre-loaded go-webauthn credentials.
func NewWebAuthnUser(u *user.User, creds []gowebauthn.Credential) *WebAuthnUser {
	return &WebAuthnUser{user: u, credentials: creds}
}

// WebAuthnID returns the user's UUID as bytes. This is the WebAuthn user handle.
func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

// WebAuthnName returns the user's username for WebAuthn ceremonies.
func (u *WebAuthnUser) WebAuthnName() string {
	return u.user.Username
}

// WebAuthnDisplayName returns the user's display name, falling back to username if empty.
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	if u.user.Name != "" {
		return u.user.Name
	}
	return u.user.Username
}

// WebAuthnCredentials returns the user's pre-loaded go-webauthn credentials.
func (u *WebAuthnUser) WebAuthnCredentials() []gowebauthn.Credential {
	return u.credentials
}
