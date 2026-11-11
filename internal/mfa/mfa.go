// Package mfa implements the two factors Passage accepts: RFC 6238 TOTP
// (SHA-1, 6 digits, 30-second steps, ±1 step of clock skew) and single-use
// recovery codes.
//
// The package is pure: no HTTP, no database, no logging. Everything that
// touches time or persistence is passed in by the caller, which keeps the
// algorithms testable with the RFC's published vectors and lets the store
// enforce anti-replay atomically.
//
// Nothing here ever exposes a plaintext code to a log. Secrets are base32
// (RFC 4648, no padding) and recovery codes are only ever handled as sha256
// hashes once issued. Secret storage is deliberately unencrypted; the SQLite
// database file is expected to be mode 0600 (see docs/security.md).
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the number of decimal digits in a TOTP code.
	Digits = 6
	// Period is the TOTP time step.
	Period = 30 * time.Second
	// Skew is how many steps either side of the current one are accepted.
	Skew = 1

	// SecretBytes is the entropy of a new TOTP secret (160 bits, the RFC 4226
	// recommendation for HMAC-SHA-1).
	SecretBytes = 20

	// RecoveryCodeCount is how many recovery codes an enrollment issues.
	RecoveryCodeCount = 10
	// recoveryCodeChars is the length of a recovery code, excluding the dash.
	recoveryCodeChars = 10

	// ChallengeTTL is how long a pending second-factor challenge stays valid.
	ChallengeTTL = 5 * time.Minute
)

// recoveryAlphabet is Crockford's base32 alphabet: digits and letters that
// survive being read off paper. I, L, O and U are excluded; NormalizeRecoveryCode
// maps the look-alikes (I/L → 1, O → 0, U → V) so a hand-typed code still works.
// 32 symbols × 10 characters = 50 bits per code.
const recoveryAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// base32NoPad encodes secrets without padding, as every authenticator app expects.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a fresh TOTP secret: 20 random bytes, base32 without
// padding, upper case.
func GenerateSecret() (string, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mfa: generate secret: %w", err)
	}
	return base32NoPad.EncodeToString(b), nil
}

// Validate checks code against secret at time now and returns the TOTP step it
// matched. Steps at or below lastStep are never accepted: the caller persists
// the accepted step, which makes a replayed code (and any code from an earlier
// window) useless even inside the skew window.
//
// The comparison is constant time. An unparsable secret or a code that is not
// exactly Digits digits is a plain false, never a panic.
func Validate(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = normalizeCode(code)
	if len(code) != Digits {
		return 0, false
	}
	key, ok := decodeSecret(secret)
	if !ok {
		return 0, false
	}

	current := now.UTC().Unix() / int64(Period/time.Second)
	want := []byte(code)
	for offset := int64(-Skew); offset <= Skew; offset++ {
		step := current + offset
		if step < 0 || step <= lastStep {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(step), Digits)), want) == 1 {
			return step, true
		}
	}
	return 0, false
}

// ProvisioningURI builds the otpauth:// URI an authenticator app consumes.
// It is shown for manual entry and for QR generation by the user's own client
// (Passage deliberately ships no QR encoder and no new dependency).
func ProvisioningURI(issuer, account, secret string) string {
	label := issuer + ":" + account
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", Digits))
	v.Set("period", fmt.Sprintf("%d", int(Period/time.Second)))
	// PathEscape keeps ':' (the issuer/account separator) and escapes spaces and
	// other reserved characters, which is the form authenticator apps expect.
	return "otpauth://totp/" + url.PathEscape(label) + "?" + v.Encode()
}

// GenerateRecoveryCodes returns n formatted recovery codes ("xxxxx-xxxxx").
// Each code carries 50 bits of crypto/rand entropy.
func GenerateRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	codes := make([]string, n)
	buf := make([]byte, recoveryCodeChars)
	for i := range codes {
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("mfa: generate recovery code: %w", err)
		}
		// 256 is an exact multiple of 32, so the modulo is unbiased.
		var sb strings.Builder
		sb.Grow(recoveryCodeChars + 1)
		for j, b := range buf {
			if j == recoveryCodeChars/2 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(b)%len(recoveryAlphabet)])
		}
		codes[i] = sb.String()
	}
	return codes, nil
}

// NormalizeRecoveryCode puts a recovery code into its canonical form: upper
// case, alphanumerics only, with Crockford's look-alike substitutions applied.
// It is idempotent, and hashing its output is what gets stored.
func NormalizeRecoveryCode(code string) string {
	var sb strings.Builder
	sb.Grow(len(code))
	for _, r := range strings.ToUpper(code) {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z':
			switch r {
			case 'I', 'L':
				r = '1'
			case 'O':
				r = '0'
			case 'U':
				r = 'V'
			}
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// HashRecoveryCode returns the hex-encoded sha256 of the normalised code. Only
// this hash is ever stored; the plaintext exists once, in the enrollment
// response.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(NormalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// FormatSecret groups a base32 secret in fours for easier manual entry.
func FormatSecret(secret string) string {
	var sb strings.Builder
	sb.Grow(len(secret) + len(secret)/4)
	for i, r := range secret {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// LooksLikeTOTP reports whether code is shaped like a TOTP code (exactly Digits
// decimal digits). Recovery codes are longer and alphanumeric, so this is the
// unambiguous discriminator between the two factors.
func LooksLikeTOTP(code string) bool {
	return len(normalizeCode(code)) == Digits
}

// hotp is RFC 4226 HOTP: HMAC-SHA-1 over the big-endian counter, dynamic
// truncation, then the decimal tail.
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binary := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, binary%mod)
}

// decodeSecret parses a stored base32 secret, tolerating lowercase, spaces and
// padding so an operator-supplied value still works.
func decodeSecret(secret string) ([]byte, bool) {
	var sb strings.Builder
	for _, r := range strings.ToUpper(secret) {
		if r == ' ' || r == '\t' || r == '-' {
			continue
		}
		sb.WriteRune(r)
	}
	s := strings.TrimRight(sb.String(), "=")
	if s == "" {
		return nil, false
	}
	key, err := base32NoPad.DecodeString(s)
	if err != nil || len(key) == 0 {
		return nil, false
	}
	return key, true
}

// normalizeCode strips every non-digit from a submitted TOTP code, so "123 456"
// and "123456" are the same input.
func normalizeCode(code string) string {
	var sb strings.Builder
	sb.Grow(len(code))
	for _, r := range code {
		if r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
