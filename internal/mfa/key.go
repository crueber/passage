package mfa

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// KeyFileSuffix is appended to the database path when no explicit key is
// configured, producing the file that holds the TOTP encryption key.
const KeyFileSuffix = ".key"

// ResolveKey returns the key that encrypts TOTP secrets at rest.
//
// Precedence:
//
//  1. configured — security.encryption_key, as 64 hex characters or the base64
//     encoding of 32 bytes.
//  2. A key file next to the database: databasePath + ".key", created on first
//     use from crypto/rand, hex encoded, mode 0600. It is deliberately stable
//     across restarts — the key must outlive the process or every enrolled
//     secret becomes unreadable.
//  3. For a ":memory:" database, a process-local key. There is no file to keep
//     it in and nothing that outlives the process.
func ResolveKey(configured, databasePath string) ([]byte, error) {
	if configured != "" {
		key, err := ParseKey(configured)
		if err != nil {
			return nil, fmt.Errorf("parse configured encryption key: %w", err)
		}
		return key, nil
	}
	if databasePath == "" {
		return nil, errors.New("mfa: database path is empty and no encryption key is configured")
	}
	if databasePath == ":memory:" {
		key, err := generateKey()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral encryption key: %w", err)
		}
		return key, nil
	}
	return loadOrCreateKeyFile(databasePath + KeyFileSuffix)
}

// ParseKey decodes a key from its textual form: 64 hex characters or the
// base64 encoding (padded or unpadded) of exactly 32 bytes.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("key is empty")
	}
	if len(s) == hex.EncodedLen(KeySize) {
		if key, err := hex.DecodeString(s); err == nil && len(key) == KeySize {
			return key, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if key, err := enc.DecodeString(s); err == nil && len(key) == KeySize {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key must be %d bytes, written as %d hex characters or base64",
		KeySize, hex.EncodedLen(KeySize))
}

// loadOrCreateKeyFile reads path, creating it with a fresh key when it is
// absent. O_CREATE|O_EXCL is the lock: if two processes start together the
// loser's open fails with "file exists" and it re-reads the winner's key, so
// both end up with the same one.
func loadOrCreateKeyFile(path string) ([]byte, error) {
	key, err := readKeyFile(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	key, err = generateKey()
	if err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Lost the creation race; the other process's key is the real one.
			return readKeyFile(path)
		}
		return nil, fmt.Errorf("create encryption key file %q: %w", path, err)
	}
	// No trailing newline: the file is exactly one hex key.
	if _, err := f.WriteString(hex.EncodeToString(key)); err != nil {
		_ = f.Close()
		// The file is ours (O_EXCL) and unusable; remove it so the next start
		// creates a complete key instead of failing on a partial one.
		_ = os.Remove(path)
		return nil, fmt.Errorf("write encryption key file %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close encryption key file %q: %w", path, err)
	}
	return key, nil
}

// readKeyFile reads one key from path. A missing file is reported as
// fs.ErrNotExist so the caller can distinguish "create it" from "it is broken".
func readKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("read encryption key file %q: %w", path, err)
	}
	key, err := ParseKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("encryption key file %q: %w", path, err)
	}
	return key, nil
}

// generateKey returns KeySize bytes of crypto/rand.
func generateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("mfa: read random key material: %w", err)
	}
	return key, nil
}
