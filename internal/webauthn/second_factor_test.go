package webauthn_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/crueber/passage/internal/user"
	"github.com/crueber/passage/internal/webauthn"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// passkeyFlagReader mirrors the settings reader webauthn.NewHandler takes, so
// tests can control the passkey enable flag without naming the unexported type.
type passkeyFlagReader interface {
	Get(ctx context.Context, key string) (string, error)
}

// newSecondFactorHandler builds a Handler around a caller-supplied challenge
// store and settings reader. The ceremony methods under test never render, so
// no template set is needed.
func newSecondFactorHandler(t *testing.T, f *handlerFixture, challenges webauthn.ChallengeStorer, settings passkeyFlagReader) *webauthn.Handler {
	t.Helper()
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPDisplayName: "Passage Test",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	})
	if err != nil {
		t.Fatalf("create webauthn: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	return webauthn.NewHandler(wa, f.credStore, challenges, f.userStore, f.sessionSvc,
		f.cfg.Session.CookieName, f.cfg.Session.CookieSecure, nil, logger, settings, nil, nil)
}

// newFixtureUser registers an active user and returns it.
func newFixtureUser(t *testing.T, f *handlerFixture, username string) *user.User {
	t.Helper()
	ctx := context.Background()
	if _, err := f.userSvc.Register(ctx, username, username+"@example.com", "password123"); err != nil {
		t.Fatalf("register %q: %v", username, err)
	}
	u, err := f.userStore.GetByUsername(ctx, username)
	if err != nil {
		t.Fatalf("get user %q: %v", username, err)
	}
	return u
}

// softwareAuthenticator is a minimal FIDO2 authenticator: one P-256 credential
// that produces assertions. It stands in for a real device (a security key or
// platform authenticator), which a headless test environment cannot drive.
type softwareAuthenticator struct {
	credID []byte
	key    *ecdsa.PrivateKey
}

func newSoftwareAuthenticator(t *testing.T) *softwareAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("generate credential id: %v", err)
	}
	return &softwareAuthenticator{credID: id, key: key}
}

// storeCredential persists the credential the way a registration ceremony
// would: the go-webauthn credential (ID, COSE public key, flags) is JSON
// marshalled into webauthn_credentials.public_key, which dbCredsToWACreds
// reverses for the ceremony.
func (a *softwareAuthenticator) storeCredential(t *testing.T, f *handlerFixture, userID string) {
	t.Helper()
	stored := gowebauthn.Credential{
		ID:              a.credID,
		PublicKey:       a.coseKey(),
		AttestationType: "none",
	}
	blob, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	err = f.credStore.Create(context.Background(), &webauthn.Credential{
		ID:        base64.RawURLEncoding.EncodeToString(a.credID),
		UserID:    userID,
		Name:      "Software authenticator",
		PublicKey: blob,
	})
	if err != nil {
		t.Fatalf("store credential: %v", err)
	}
}

// coseKey hand-encodes the COSE_Key (RFC 8152) for an ES256 P-256 key:
// {1: 2, 3: -7, -1: 1, -2: x, -3: y}. Encoding it by hand keeps the test free
// of a CBOR dependency.
func (a *softwareAuthenticator) coseKey() []byte {
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	b := []byte{
		0xa5,       // map(5)
		0x01, 0x02, //  1 (kty): 2 (EC2)
		0x03, 0x26, //  3 (alg): -7 (ES256)
		0x20, 0x01, // -1 (crv): 1 (P-256)
		0x21, 0x58, 0x20, // -2 (x): bytes(32)
	}
	b = append(b, x...)
	b = append(b, 0x22, 0x58, 0x20) // -3 (y): bytes(32)
	return append(b, y...)
}

// assertion builds the JSON body a browser would post for options, signed by
// the software authenticator. flags is the authenticator-data flag byte (UP is
// 0x01, UV is 0x04); userHandle may be nil.
func (a *softwareAuthenticator) assertion(t *testing.T, options *protocol.CredentialAssertion, userHandle []byte, flags byte, signCount uint32) *http.Request {
	t.Helper()
	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   options.Response.Challenge.String(),
		"origin":      "http://localhost:8080",
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}

	rpIDHash := sha256.Sum256([]byte("localhost"))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], signCount)
	authData = append(authData, counter[:]...)

	clientDataHash := sha256.Sum256(clientData)
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(userHandle),
		},
	})
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/login/mfa/passkey/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// beginSecondFactor starts a ceremony and decodes the options it returns.
func beginSecondFactor(t *testing.T, h *webauthn.Handler, u *user.User, bindKey string) *protocol.CredentialAssertion {
	t.Helper()
	body, err := h.BeginSecondFactor(context.Background(), u, bindKey)
	if err != nil {
		t.Fatalf("BeginSecondFactor: %v", err)
	}
	var options protocol.CredentialAssertion
	if err := json.Unmarshal(body, &options); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	return &options
}

// ─── tests ───────────────────────────────────────────────────────────────────

// TestHasCredentials covers the decision the second-factor page uses to offer
// the passkey option.
func TestHasCredentials(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	ctx := context.Background()

	withCred := newFixtureUser(t, f, "has-passkey")
	withoutCred := newFixtureUser(t, f, "no-passkey")
	newSoftwareAuthenticator(t).storeCredential(t, f, withCred.ID)

	has, err := h.HasCredentials(ctx, withCred.ID)
	if err != nil {
		t.Fatalf("HasCredentials: %v", err)
	}
	if !has {
		t.Error("HasCredentials = false for a user with a credential")
	}

	has, err = h.HasCredentials(ctx, withoutCred.ID)
	if err != nil {
		t.Fatalf("HasCredentials: %v", err)
	}
	if has {
		t.Error("HasCredentials = true for a user without credentials")
	}
}

// TestBeginSecondFactor_AllowListAndUserVerification proves the options are a
// non-discoverable, user-verification-required assertion restricted to the
// user's own credential.
func TestBeginSecondFactor_AllowListAndUserVerification(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	u := newFixtureUser(t, f, "begin-user")
	auth := newSoftwareAuthenticator(t)
	auth.storeCredential(t, f, u.ID)

	options := beginSecondFactor(t, h, u, "challenge-token")

	if got := options.Response.RelyingPartyID; got != "localhost" {
		t.Errorf("rpId = %q, want localhost", got)
	}
	if got := options.Response.UserVerification; got != protocol.VerificationRequired {
		t.Errorf("userVerification = %q, want %q", got, protocol.VerificationRequired)
	}
	if len(options.Response.AllowedCredentials) != 1 {
		t.Fatalf("allowCredentials has %d entries, want 1", len(options.Response.AllowedCredentials))
	}
	if got := options.Response.AllowedCredentials[0].CredentialID; !bytes.Equal(got, auth.credID) {
		t.Errorf("allowCredentials[0] = %x, want %x", got, auth.credID)
	}
	if len(options.Response.Challenge) == 0 {
		t.Error("options carry no challenge")
	}
}

// TestFinishSecondFactor_VerifiesAndConsumes is the happy path: a valid
// assertion for the bound challenge succeeds once, updates the sign counter,
// and cannot be replayed against the same ceremony.
func TestFinishSecondFactor_VerifiesAndConsumes(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	ctx := context.Background()
	u := newFixtureUser(t, f, "finish-user")
	auth := newSoftwareAuthenticator(t)
	auth.storeCredential(t, f, u.ID)

	options := beginSecondFactor(t, h, u, "bind-key-1")
	// Bit 0 is UP, bit 2 is UV: a second factor requires both.
	if err := h.FinishSecondFactor(ctx, auth.assertion(t, options, []byte(u.ID), 0x05, 1), u, "bind-key-1"); err != nil {
		t.Fatalf("FinishSecondFactor: %v", err)
	}

	cred, err := f.credStore.GetByID(ctx, base64.RawURLEncoding.EncodeToString(auth.credID))
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if cred.SignCount != 1 {
		t.Errorf("stored sign count = %d, want 1", cred.SignCount)
	}

	// The ceremony was consumed before verification: the same challenge cannot
	// be asserted again, even with a freshly signed assertion.
	if err := h.FinishSecondFactor(ctx, auth.assertion(t, options, []byte(u.ID), 0x05, 2), u, "bind-key-1"); err == nil {
		t.Error("a second FinishSecondFactor for the same ceremony succeeded")
	}
}

// TestFinishSecondFactor_BindKeyIsolation is the core binding property: a
// ceremony begun for challenge A cannot complete challenge B, and failing that
// way does not disturb A's ceremony.
func TestFinishSecondFactor_BindKeyIsolation(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	ctx := context.Background()
	u := newFixtureUser(t, f, "isolation-user")
	auth := newSoftwareAuthenticator(t)
	auth.storeCredential(t, f, u.ID)

	optionsA := beginSecondFactor(t, h, u, "challenge-a")

	if err := h.FinishSecondFactor(ctx, auth.assertion(t, optionsA, []byte(u.ID), 0x05, 1), u, "challenge-b"); err == nil {
		t.Fatal("an assertion begun for challenge A completed challenge B")
	}

	// A's ceremony is untouched by the failed B lookup.
	if err := h.FinishSecondFactor(ctx, auth.assertion(t, optionsA, []byte(u.ID), 0x05, 2), u, "challenge-a"); err != nil {
		t.Fatalf("finish for challenge A after isolation failure: %v", err)
	}
}

// TestFinishSecondFactor_RequiresUserVerification proves a user-present-only
// assertion (no UV flag) is refused: the second factor must verify the person.
func TestFinishSecondFactor_RequiresUserVerification(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	u := newFixtureUser(t, f, "uv-user")
	auth := newSoftwareAuthenticator(t)
	auth.storeCredential(t, f, u.ID)

	options := beginSecondFactor(t, h, u, "uv-bind")
	err := h.FinishSecondFactor(context.Background(), auth.assertion(t, options, []byte(u.ID), 0x01, 1), u, "uv-bind")
	if err == nil {
		t.Fatal("assertion without the user-verified flag was accepted")
	}
}

// TestFinishSecondFactor_RejectsForeignUserHandle proves the returned user
// handle must belong to the challenge's user.
func TestFinishSecondFactor_RejectsForeignUserHandle(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	u := newFixtureUser(t, f, "handle-user")
	other := newFixtureUser(t, f, "handle-other")
	auth := newSoftwareAuthenticator(t)
	auth.storeCredential(t, f, u.ID)

	options := beginSecondFactor(t, h, u, "handle-bind")
	err := h.FinishSecondFactor(context.Background(), auth.assertion(t, options, []byte(other.ID), 0x05, 1), u, "handle-bind")
	if err == nil {
		t.Fatal("assertion carrying another user's handle was accepted")
	}
}

// TestBeginSecondFactor_NoCredentials proves a user without a passkey gets no
// ceremony.
func TestBeginSecondFactor_NoCredentials(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	u := newFixtureUser(t, f, "credless")

	if _, err := h.BeginSecondFactor(context.Background(), u, "bind"); err == nil {
		t.Fatal("BeginSecondFactor succeeded for a user without credentials")
	}
}

// TestSecondFactor_ChallengeExpired proves a stale ceremony cannot be finished.
func TestSecondFactor_ChallengeExpired(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	challenges := webauthn.NewChallengeStoreWithTTL(1 * time.Millisecond)
	h := newSecondFactorHandler(t, f, challenges, nil)
	u := newFixtureUser(t, f, "expired-user")
	auth := newSoftwareAuthenticator(t)
	auth.storeCredential(t, f, u.ID)

	options := beginSecondFactor(t, h, u, "expired-bind")
	time.Sleep(5 * time.Millisecond)

	err := h.FinishSecondFactor(context.Background(), auth.assertion(t, options, []byte(u.ID), 0x05, 1), u, "expired-bind")
	if err == nil {
		t.Fatal("expired ceremony was accepted")
	}
}

// TestSecondFactor_PasskeyDisabled proves the ceremony refuses to run when the
// passkey auth method is turned off, even for a user who has a credential.
func TestSecondFactor_PasskeyDisabled(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), disabledPasskeySettings{})
	u := newFixtureUser(t, f, "disabled-user")
	auth := newSoftwareAuthenticator(t)
	auth.storeCredential(t, f, u.ID)

	if _, err := h.BeginSecondFactor(context.Background(), u, "disabled-bind"); err == nil {
		t.Fatal("BeginSecondFactor succeeded while passkeys are disabled")
	}

	// Even a ceremony issued elsewhere cannot be finished while disabled: the
	// flag is checked before any ceremony state is read.
	enabled := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	options := beginSecondFactor(t, enabled, u, "disabled-bind")
	body := auth.assertion(t, options, []byte(u.ID), 0x05, 1)
	if err := h.FinishSecondFactor(context.Background(), body, u, "bind"); err == nil {
		t.Fatal("FinishSecondFactor succeeded while passkeys are disabled")
	}
}

// TestSecondFactor_InactiveUser proves the ceremony refuses a deactivated
// account even if a caller hands it one: the HTTP layer checks first, but the
// ceremony is the security boundary and must not depend on that.
func TestSecondFactor_InactiveUser(t *testing.T) {
	t.Parallel()
	f := newHandlerFixture(t)
	h := newSecondFactorHandler(t, f, webauthn.NewChallengeStore(), nil)
	u := newFixtureUser(t, f, "inactive-user")
	auth := newSoftwareAuthenticator(t)
	auth.storeCredential(t, f, u.ID)

	options := beginSecondFactor(t, h, u, "inactive-bind")
	u.IsActive = false

	if _, err := h.BeginSecondFactor(context.Background(), u, "inactive-bind"); err == nil {
		t.Error("BeginSecondFactor accepted an inactive user")
	}
	err := h.FinishSecondFactor(context.Background(), auth.assertion(t, options, []byte(u.ID), 0x05, 1), u, "inactive-bind")
	if err == nil {
		t.Error("FinishSecondFactor accepted an inactive user")
	}
}
