package mfa

import (
	"strings"
	"testing"
	"time"
)

// rfc6238Seed is the seed from RFC 6238 appendix B.
const rfc6238Seed = "12345678901234567890"

func rfcKey(t *testing.T) []byte {
	t.Helper()
	return []byte(rfc6238Seed)
}

// TestHOTP_RFC6238Vectors checks the RFC 6238 appendix B SHA-1 vectors. The
// published vectors are 8 digits; the HOTP core is shared with the 6-digit
// production path, so pinning it here pins the algorithm.
func TestHOTP_RFC6238Vectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		unix    int64
		wantOTP string
	}{
		{"T=59", 59, "94287082"},
		{"T=1111111109", 1111111109, "07081804"},
		{"T=1111111111", 1111111111, "14050471"},
		{"T=1234567890", 1234567890, "89005924"},
		{"T=2000000000", 2000000000, "69279037"},
		{"T=20000000000", 20000000000, "65353130"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			counter := uint64(tt.unix / int64(Period/time.Second))
			if got := hotp(rfcKey(t), counter, 8); got != tt.wantOTP {
				t.Errorf("hotp(counter=%d, 8) = %q; want %q", counter, got, tt.wantOTP)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	// A fixed secret and clock so the expected code is deterministic.
	secret := base32NoPad.EncodeToString(rfcKey(t))
	at := time.Unix(1111111111, 0).UTC()

	codeAt := func(delta time.Duration) string {
		step := uint64(at.Add(delta).Unix() / int64(Period/time.Second))
		return hotp(rfcKey(t), step, Digits)
	}

	tests := []struct {
		name     string
		secret   string
		code     string
		now      time.Time
		lastStep int64
		wantOK   bool
		wantStep int64
	}{
		{
			name:   "current step",
			secret: secret,
			code:   codeAt(0),
			now:    at,
			// 1111111111 / 30 = 37037037.03 → step 37037037
			wantOK:   true,
			wantStep: 37037037,
		},
		{
			name:     "previous step within skew",
			secret:   secret,
			code:     codeAt(-Period),
			now:      at,
			wantOK:   true,
			wantStep: 37037036,
		},
		{
			name:     "next step within skew",
			secret:   secret,
			code:     codeAt(Period),
			now:      at,
			wantOK:   true,
			wantStep: 37037038,
		},
		{
			name:   "two steps old is outside skew",
			secret: secret,
			code:   codeAt(-2 * Period),
			now:    at,
			wantOK: false,
		},
		{
			name:     "step at the watermark is a replay",
			secret:   secret,
			code:     codeAt(0),
			now:      at,
			lastStep: 37037037,
			wantOK:   false,
		},
		{
			name:     "step below the watermark is a replay",
			secret:   secret,
			code:     codeAt(-Period),
			now:      at,
			lastStep: 37037037,
			wantOK:   false,
		},
		{
			name:     "step above the watermark is accepted",
			secret:   secret,
			code:     codeAt(Period),
			now:      at,
			lastStep: 37037037,
			wantOK:   true,
			wantStep: 37037038,
		},
		{
			name:   "wrong code",
			secret: secret,
			code:   "000000",
			now:    at,
			wantOK: false,
		},
		{
			name:     "code with spaces is normalised",
			secret:   secret,
			code:     spaced(codeAt(0)),
			now:      at,
			wantOK:   true,
			wantStep: 37037037,
		},
		{
			name:   "too short",
			secret: secret,
			code:   "12345",
			now:    at,
			wantOK: false,
		},
		{
			name:   "too long",
			secret: secret,
			code:   "1234567",
			now:    at,
			wantOK: false,
		},
		{
			name:   "letters only",
			secret: secret,
			code:   "abcdef",
			now:    at,
			wantOK: false,
		},
		{
			name:   "empty code",
			secret: secret,
			code:   "",
			now:    at,
			wantOK: false,
		},
		{
			name:   "empty secret",
			secret: "",
			code:   codeAt(0),
			now:    at,
			wantOK: false,
		},
		{
			name:   "garbage secret",
			secret: "not base32 !!!",
			code:   codeAt(0),
			now:    at,
			wantOK: false,
		},
		{
			name:     "lowercase secret and padded secret still work",
			secret:   strings.ToLower(secret) + "==",
			code:     codeAt(0),
			now:      at,
			wantOK:   true,
			wantStep: 37037037,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			step, ok := Validate(tt.secret, tt.code, tt.now, tt.lastStep)
			if ok != tt.wantOK {
				t.Fatalf("Validate() ok = %v; want %v", ok, tt.wantOK)
			}
			if ok && step != tt.wantStep {
				t.Errorf("Validate() step = %d; want %d", step, tt.wantStep)
			}
			if !ok && step != 0 {
				t.Errorf("Validate() step = %d on failure; want 0", step)
			}
		})
	}
}

func TestGenerateSecret(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := GenerateSecret()
		if err != nil {
			t.Fatalf("GenerateSecret: %v", err)
		}
		if strings.ContainsAny(s, "= \t\n") {
			t.Errorf("secret %q contains padding or whitespace", s)
		}
		if s != strings.ToUpper(s) {
			t.Errorf("secret %q is not upper case", s)
		}
		key, err := base32NoPad.DecodeString(s)
		if err != nil {
			t.Fatalf("secret %q does not decode: %v", s, err)
		}
		if len(key) != SecretBytes {
			t.Errorf("secret decodes to %d bytes; want %d", len(key), SecretBytes)
		}
		if seen[s] {
			t.Fatalf("GenerateSecret returned a duplicate: %q", s)
		}
		seen[s] = true
	}
}

func TestProvisioningURI(t *testing.T) {
	t.Parallel()

	uri := ProvisioningURI("Passage", "alice@example.com", "JBSWY3DPEHPK3PXP")
	for _, want := range []string{
		"otpauth://totp/",
		"Passage:alice@example.com",
		"secret=JBSWY3DPEHPK3PXP",
		"issuer=Passage",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("ProvisioningURI() = %q; missing %q", uri, want)
		}
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	t.Parallel()

	codes, err := GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("got %d codes; want %d", len(codes), RecoveryCodeCount)
	}

	seen := make(map[string]bool)
	for _, c := range codes {
		if len(c) != recoveryCodeChars+1 || c[5] != '-' {
			t.Errorf("code %q is not in xxxxx-xxxxx form", c)
		}
		if seen[c] {
			t.Errorf("duplicate recovery code %q", c)
		}
		seen[c] = true
		for _, r := range strings.ReplaceAll(c, "-", "") {
			if !strings.ContainsRune(recoveryAlphabet, r) {
				t.Errorf("code %q contains %q, outside the unambiguous alphabet", c, r)
			}
		}
		if HashRecoveryCode(c) == "" {
			t.Errorf("code %q has no hash", c)
		}
	}
}

func TestNormalizeAndHashRecoveryCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already normal", "ABCDE-23456", "ABCDE23456"},
		{"lower case", "abcde-23456", "ABCDE23456"},
		{"spaces and dashes", " ABCDE 23456 ", "ABCDE23456"},
		{"look-alikes", "IOLU-ABCDE", "101VABCDE"},
		{"idempotent", "1O1V-ABCDE", "101VABCDE"},
		{"punctuation", "AB!CD@E#23$45%6", "ABCDE23456"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeRecoveryCode(tt.in)
			if got != tt.want {
				t.Fatalf("NormalizeRecoveryCode(%q) = %q; want %q", tt.in, got, tt.want)
			}
			if again := NormalizeRecoveryCode(got); again != got {
				t.Errorf("NormalizeRecoveryCode is not idempotent: %q → %q", got, again)
			}
			if HashRecoveryCode(tt.in) != HashRecoveryCode(tt.want) {
				t.Errorf("hash differs between raw and normalised input for %q", tt.in)
			}
		})
	}

	// A hash is stable and 64 hex characters (sha256).
	h := HashRecoveryCode("ABCDE-23456")
	if len(h) != 64 {
		t.Errorf("HashRecoveryCode length = %d; want 64", len(h))
	}
	if h != HashRecoveryCode("abcde 23456") {
		t.Error("HashRecoveryCode is not stable across formatting")
	}
	if h == HashRecoveryCode("ABCDE-23457") {
		t.Error("different codes produced the same hash")
	}
}

func TestFormatSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"AB", "AB"},
		{"ABCD", "ABCD"},
		{"ABCDE", "ABCD E"},
		{"ABCDEFGHIJKL", "ABCD EFGH IJKL"},
	}
	for _, tt := range tests {
		if got := FormatSecret(tt.in); got != tt.want {
			t.Errorf("FormatSecret(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

func TestLooksLikeTOTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want bool
	}{
		{"123456", true},
		{"123 456", true},
		{"12345", false},
		{"1234567", false},
		{"ABCDE-23456", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := LooksLikeTOTP(tt.in); got != tt.want {
			t.Errorf("LooksLikeTOTP(%q) = %v; want %v", tt.in, got, tt.want)
		}
	}
}

// spaced inserts spaces into a code to exercise normalisation.
func spaced(code string) string {
	var sb strings.Builder
	for i, r := range code {
		if i == len(code)/2 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
