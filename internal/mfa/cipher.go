package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	// KeySize is the AES-256 key length in bytes.
	KeySize = 32

	// cipherPrefix marks a stored value as encrypted by this package. The
	// version is part of the value, not the schema, so a future algorithm or
	// key change can be detected without a migration.
	cipherPrefix = "v1:"

	// nonceSize is the standard GCM nonce length.
	nonceSize = 12
)

// ErrDecrypt means a stored secret could not be decrypted: the value was
// tampered with, it was copied to another user's row (the user ID is the AAD),
// or it was encrypted with a different key. It deliberately carries no detail
// about which of those happened.
var ErrDecrypt = errors.New("mfa: encrypted secret cannot be decrypted")

// Cipher encrypts TOTP secrets at rest with AES-256-GCM.
//
// Every value gets a fresh random 96-bit nonce, and the owning user's ID is
// bound in as additional authenticated data, so a ciphertext moved between
// rows fails authentication instead of silently transferring a second factor.
// The stored form is "v1:" + base64(nonce||ciphertext).
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a Cipher from a 32-byte AES-256 key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("mfa: cipher key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mfa: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mfa: create GCM: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals secret, binding it to aad (the user ID). The returned value is
// the form stored in user_mfa.secret.
func (c *Cipher) Encrypt(secret, aad string) (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("mfa: read encryption nonce: %w", err)
	}
	// Seal appends the ciphertext and tag to nonce, so the result is
	// nonce||ciphertext||tag — everything needed to open it, apart from aad.
	sealed := c.aead.Seal(nonce, nonce, []byte(secret), []byte(aad))
	return cipherPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens value, which must have been encrypted for aad (the user ID).
//
// A value without the version prefix is returned unchanged. That is the legacy
// contract: a database written by a release that stored secrets in plain text
// keeps working, for reads and for TOTP verification, until ReencryptSecrets
// has rewritten it.
func (c *Cipher) Decrypt(value, aad string) (string, error) {
	if !IsEncrypted(value) {
		return value, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, cipherPrefix))
	if err != nil {
		return "", fmt.Errorf("%w: invalid encoding", ErrDecrypt)
	}
	if len(raw) < nonceSize+c.aead.Overhead() {
		return "", fmt.Errorf("%w: value is truncated", ErrDecrypt)
	}
	plain, err := c.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], []byte(aad))
	if err != nil {
		// Opaque on purpose: a caller (and an attacker reading logs) learns
		// only that the value did not authenticate.
		return "", fmt.Errorf("%w: authentication failed", ErrDecrypt)
	}
	return string(plain), nil
}

// IsEncrypted reports whether value is in the encrypted storage format. It needs
// no key, so it is also the test a re-encryption pass uses on raw column values.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, cipherPrefix)
}
