package mfa_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crueber/passage/internal/mfa"
)

// fixedKey is a deterministic 32-byte key, so failures point at the code rather
// than at random material.
var fixedKey = []byte("0123456789abcdef0123456789abcdef")

func newCipher(t *testing.T, key []byte) *mfa.Cipher {
	t.Helper()
	c, err := mfa.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestCipher_RoundTrip(t *testing.T) {
	t.Parallel()
	c := newCipher(t, fixedKey)
	const secret = "JBSWY3DPEHPK3PXP"

	sealed, err := c.Encrypt(secret, "alice")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(sealed, "v1:") {
		t.Errorf("Encrypt() = %q; want a v1: prefix", sealed)
	}
	if !mfa.IsEncrypted(sealed) {
		t.Error("IsEncrypted() = false for an encrypted value")
	}
	if strings.Contains(sealed, secret) {
		t.Error("ciphertext contains the plaintext secret")
	}

	got, err := c.Decrypt(sealed, "alice")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != secret {
		t.Errorf("Decrypt() = %q; want %q", got, secret)
	}

	// A fresh nonce every time: the same secret must not produce the same
	// stored value, or the column would leak equality between users.
	seen := map[string]bool{sealed: true}
	for i := 0; i < 50; i++ {
		again, err := c.Encrypt(secret, "alice")
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if seen[again] {
			t.Fatal("Encrypt reused a nonce / produced a duplicate ciphertext")
		}
		seen[again] = true
	}
}

func TestCipher_WrongAADFails(t *testing.T) {
	t.Parallel()
	c := newCipher(t, fixedKey)

	sealed, err := c.Encrypt("JBSWY3DPEHPK3PXP", "alice")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The user ID is the AAD: a ciphertext moved to another user's row must not
	// silently become that user's second factor.
	if _, err := c.Decrypt(sealed, "bob"); !errors.Is(err, mfa.ErrDecrypt) {
		t.Fatalf("Decrypt with wrong AAD = %v; want ErrDecrypt", err)
	}
	if _, err := c.Decrypt(sealed, ""); !errors.Is(err, mfa.ErrDecrypt) {
		t.Fatalf("Decrypt with empty AAD = %v; want ErrDecrypt", err)
	}
}

func TestCipher_WrongKeyFails(t *testing.T) {
	t.Parallel()
	sealed, err := newCipher(t, fixedKey).Encrypt("JBSWY3DPEHPK3PXP", "alice")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	other := []byte("fedcba9876543210fedcba9876543210")
	if _, err := newCipher(t, other).Decrypt(sealed, "alice"); !errors.Is(err, mfa.ErrDecrypt) {
		t.Fatalf("Decrypt under the wrong key = %v; want ErrDecrypt", err)
	}
}

func TestCipher_TamperedValueFails(t *testing.T) {
	t.Parallel()
	c := newCipher(t, fixedKey)

	sealed, err := c.Encrypt("JBSWY3DPEHPK3PXP", "alice")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, "v1:"))
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}

	flipped := append([]byte(nil), raw...)
	flipped[len(flipped)-1] ^= 0x01

	tests := []struct {
		name  string
		value string
	}{
		{"flipped tag", "v1:" + base64.StdEncoding.EncodeToString(flipped)},
		{"truncated", "v1:" + base64.StdEncoding.EncodeToString(raw[:len(raw)-1])},
		{"too short", "v1:AAAA"},
		{"not base64", "v1:not-base64!!"},
		{"empty payload", "v1:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := c.Decrypt(tt.value, "alice"); !errors.Is(err, mfa.ErrDecrypt) {
				t.Fatalf("Decrypt(%q) = %v; want ErrDecrypt", tt.value, err)
			}
		})
	}
}

// TestCipher_LegacyPassthrough pins the upgrade contract: a value written
// before encryption existed is returned unchanged, never rejected.
func TestCipher_LegacyPassthrough(t *testing.T) {
	t.Parallel()
	c := newCipher(t, fixedKey)

	tests := []struct {
		name  string
		value string
	}{
		{"base32 secret", "JBSWY3DPEHPK3PXP"},
		{"empty", ""},
		{"garbage", "not base32 !!!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := c.Decrypt(tt.value, "alice")
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", tt.value, err)
			}
			if got != tt.value {
				t.Errorf("Decrypt(%q) = %q; want it unchanged", tt.value, got)
			}
			if mfa.IsEncrypted(tt.value) {
				t.Errorf("IsEncrypted(%q) = true; want false", tt.value)
			}
		})
	}
}

func TestNewCipher_RejectsWrongKeySize(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		key := make([]byte, size)
		if _, err := mfa.NewCipher(key); err == nil {
			t.Errorf("NewCipher(%d-byte key) succeeded; want an error", size)
		}
	}
	if _, err := mfa.NewCipher(nil); err == nil {
		t.Error("NewCipher(nil) succeeded; want an error")
	}
}

func TestParseKey(t *testing.T) {
	t.Parallel()

	key := make([]byte, mfa.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("read random key: %v", err)
	}
	hexKey := hex.EncodeToString(key)
	b64Key := base64.StdEncoding.EncodeToString(key)
	rawB64Key := base64.RawStdEncoding.EncodeToString(key)

	valid := []struct {
		name string
		in   string
	}{
		{"hex", hexKey},
		{"upper-case hex", strings.ToUpper(hexKey)},
		{"hex with surrounding whitespace", "  " + hexKey + "\n"},
		{"base64 padded", b64Key},
		{"base64 unpadded", rawB64Key},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := mfa.ParseKey(tt.in)
			if err != nil {
				t.Fatalf("ParseKey(%q): %v", tt.in, err)
			}
			if string(got) != string(key) {
				t.Errorf("ParseKey(%q) decoded to %x; want %x", tt.in, got, key)
			}
		})
	}

	invalid := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t"},
		{"short hex", hexKey[:62]},
		{"long hex", hexKey + "00"},
		{"garbage", "this is not a key"},
		{"base64 of 16 bytes", base64.StdEncoding.EncodeToString(key[:16])},
		{"32 characters", strings.Repeat("a", 32)},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := mfa.ParseKey(tt.in); err == nil {
				t.Errorf("ParseKey(%q) succeeded; want an error", tt.in)
			}
		})
	}
}

func TestResolveKey_ConfiguredWins(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "passage.db")
	configured := strings.Repeat("ab", mfa.KeySize)

	key, err := mfa.ResolveKey(configured, dbPath)
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	if got, want := hex.EncodeToString(key), configured; got != want {
		t.Errorf("ResolveKey key = %s; want %s", got, want)
	}
	if _, err := os.Stat(dbPath + mfa.KeyFileSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a key file was created for an explicitly configured key: %v", err)
	}

	if _, err := mfa.ResolveKey("too-short", dbPath); err == nil {
		t.Error("ResolveKey with an invalid configured key succeeded; want an error")
	}
	if _, err := mfa.ResolveKey("", ""); err == nil {
		t.Error("ResolveKey with no key and no database path succeeded; want an error")
	}
}

func TestResolveKey_KeyFileIsStableAndPrivate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "passage.db")
	keyPath := dbPath + mfa.KeyFileSuffix

	key, err := mfa.ResolveKey("", dbPath)
	if err != nil {
		t.Fatalf("ResolveKey (create): %v", err)
	}
	if len(key) != mfa.KeySize {
		t.Fatalf("key length = %d; want %d", len(key), mfa.KeySize)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %04o; want 0600", perm)
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != hex.EncodeToString(key) {
		t.Errorf("key file contents = %q; want the hex key", got)
	}

	// The file is the stable source of truth: a second resolution (a restart)
	// must return the same key rather than mint a new one.
	again, err := mfa.ResolveKey("", dbPath)
	if err != nil {
		t.Fatalf("ResolveKey (reload): %v", err)
	}
	if string(again) != string(key) {
		t.Error("ResolveKey returned a different key on reload")
	}
}

func TestResolveKey_KeyFileAcceptsBothFormats(t *testing.T) {
	t.Parallel()

	key := make([]byte, mfa.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("read random key: %v", err)
	}

	for _, tt := range []struct {
		name    string
		content string
	}{
		{"hex", hex.EncodeToString(key)},
		{"base64", base64.StdEncoding.EncodeToString(key)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dbPath := filepath.Join(t.TempDir(), "passage.db")
			if err := os.WriteFile(dbPath+mfa.KeyFileSuffix, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("seed key file: %v", err)
			}
			got, err := mfa.ResolveKey("", dbPath)
			if err != nil {
				t.Fatalf("ResolveKey: %v", err)
			}
			if string(got) != string(key) {
				t.Errorf("ResolveKey decoded %x; want %x", got, key)
			}
		})
	}
}

func TestResolveKey_KeyFileErrors(t *testing.T) {
	t.Parallel()

	t.Run("corrupt key file is an error, not a new key", func(t *testing.T) {
		t.Parallel()
		dbPath := filepath.Join(t.TempDir(), "passage.db")
		if err := os.WriteFile(dbPath+mfa.KeyFileSuffix, []byte("nonsense"), 0o600); err != nil {
			t.Fatalf("seed key file: %v", err)
		}
		if _, err := mfa.ResolveKey("", dbPath); err == nil {
			t.Fatal("ResolveKey with a corrupt key file succeeded; want an error")
		} else if !strings.Contains(err.Error(), mfa.KeyFileSuffix) {
			t.Errorf("error %q does not name the key file", err)
		}
	})

	t.Run("unwritable directory is an error", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() == 0 {
			t.Skip("directory permissions do not apply to root")
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if _, err := mfa.ResolveKey("", filepath.Join(dir, "passage.db")); err == nil {
			t.Fatal("ResolveKey in an unwritable directory succeeded; want an error")
		}
	})
}

func TestResolveKey_MemoryIsEphemeral(t *testing.T) {
	t.Parallel()

	first, err := mfa.ResolveKey("", ":memory:")
	if err != nil {
		t.Fatalf("ResolveKey(:memory:): %v", err)
	}
	second, err := mfa.ResolveKey("", ":memory:")
	if err != nil {
		t.Fatalf("ResolveKey(:memory:) again: %v", err)
	}
	if len(first) != mfa.KeySize || len(second) != mfa.KeySize {
		t.Fatalf("key lengths = %d, %d; want %d", len(first), len(second), mfa.KeySize)
	}
	if string(first) == string(second) {
		t.Error(":memory: resolved the same key twice; want a fresh ephemeral key")
	}
}
