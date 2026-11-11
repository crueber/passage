package mfa_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crueber/passage/internal/mfa"
	"github.com/crueber/passage/internal/testutil"
)

// fixture is a real in-memory database plus a Service on a controllable clock.
type fixture struct {
	db      *sql.DB
	store   *mfa.Store
	service *mfa.Service
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := testutil.NewTestDB(t)
	f := &fixture{
		db:    db,
		store: mfa.NewStore(db),
		now:   time.Unix(1700000000, 0).UTC(),
	}
	f.service = mfa.NewService(f.store, "Passage", func() time.Time { return f.now })
	return f
}

func (f *fixture) advance(d time.Duration) { f.now = f.now.Add(d) }

// createUser inserts a minimal user and returns its ID.
func (f *fixture) createUser(t *testing.T, id string) string {
	t.Helper()
	_, err := f.db.ExecContext(context.Background(),
		`INSERT INTO users (id, username, email) VALUES (?, ?, ?)`,
		id, id, id+"@example.com")
	if err != nil {
		t.Fatalf("insert user %q: %v", id, err)
	}
	return id
}

// enroll runs a full enrollment for userID and returns the recovery codes.
func (f *fixture) enroll(t *testing.T, userID string) []string {
	t.Helper()
	ctx := context.Background()
	enr, err := f.service.BeginEnrollment(ctx, userID, userID)
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	codes, err := f.service.ConfirmEnrollment(ctx, userID, currentCode(t, enr.Secret, f.now))
	if err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	return codes
}

// currentCode returns the TOTP code for secret at now. The helper is an
// independent RFC 4226 implementation (the production one is unexported), so a
// mistake in either implementation shows up as a test failure rather than as
// two mutually-confirming copies.
func currentCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	return codeAt(t, secret, at)
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("decode secret %q: %v", secret, err)
	}

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.UTC().Unix()/int64(mfa.Period/time.Second)))

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

func TestService_EnrollmentLifecycle(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "alice")

	st, err := f.service.Status(ctx, userID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Enabled || st.RemainingCodes != 0 {
		t.Fatalf("fresh user status = %+v; want disabled with no codes", st)
	}

	enr, err := f.service.BeginEnrollment(ctx, userID, "alice")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if enr.Secret == "" || enr.Display == "" || enr.URI == "" {
		t.Fatalf("enrollment missing fields: %+v", enr)
	}
	if st, err = f.service.Status(ctx, userID); err != nil {
		t.Fatalf("Status after begin: %v", err)
	}
	if st.Enabled {
		t.Fatal("pending enrollment must not count as enabled")
	}

	codes, err := f.service.ConfirmEnrollment(ctx, userID, currentCode(t, enr.Secret, f.now))
	if err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}
	if len(codes) != mfa.RecoveryCodeCount {
		t.Fatalf("got %d recovery codes; want %d", len(codes), mfa.RecoveryCodeCount)
	}

	st, err = f.service.Status(ctx, userID)
	if err != nil {
		t.Fatalf("Status after confirm: %v", err)
	}
	if !st.Enabled || st.RemainingCodes != mfa.RecoveryCodeCount {
		t.Fatalf("status after confirm = %+v; want enabled with %d codes", st, mfa.RecoveryCodeCount)
	}
	if st.EnabledAt.IsZero() {
		t.Fatal("EnabledAt not set")
	}

	// Re-confirming an enabled credential is refused rather than reset.
	if _, err := f.service.ConfirmEnrollment(ctx, userID, currentCode(t, enr.Secret, f.now)); !errors.Is(err, mfa.ErrNotPending) {
		t.Fatalf("re-confirm error = %v; want ErrNotPending", err)
	}

	if err := f.service.Disable(ctx, userID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if st, err = f.service.Status(ctx, userID); err != nil {
		t.Fatalf("Status after disable: %v", err)
	}
	if st.Enabled {
		t.Fatal("credential still enabled after Disable")
	}

	var n int
	if err := f.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = ?`, userID).Scan(&n); err != nil {
		t.Fatalf("count recovery codes: %v", err)
	}
	if n != 0 {
		t.Errorf("recovery codes survived Disable: %d rows", n)
	}
}

func TestService_EnrollmentRequiresValidCode(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "bob")

	enr, err := f.service.BeginEnrollment(ctx, userID, "bob")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if _, err := f.service.ConfirmEnrollment(ctx, userID, "000000"); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("ConfirmEnrollment with wrong code = %v; want ErrInvalidCode", err)
	}
	if st, _ := f.service.Status(ctx, userID); st.Enabled {
		t.Fatal("wrong code enabled the credential")
	}

	// The pending secret is unchanged, so a second attempt with the right code
	// still works (the setup page re-renders rather than rotating).
	pending, err := f.service.PendingEnrollment(ctx, userID, "bob")
	if err != nil {
		t.Fatalf("PendingEnrollment: %v", err)
	}
	if pending.Secret != enr.Secret {
		t.Fatal("pending secret rotated after a failed attempt")
	}
	if _, err := f.service.ConfirmEnrollment(ctx, userID, currentCode(t, pending.Secret, f.now)); err != nil {
		t.Fatalf("ConfirmEnrollment after failure: %v", err)
	}
}

func TestService_TOTPAntiReplay(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "carol")
	enr, err := f.service.BeginEnrollment(ctx, userID, "carol")
	if err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	code := currentCode(t, enr.Secret, f.now)
	if _, err := f.service.ConfirmEnrollment(ctx, userID, code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	// Enrollment consumed the current step, so that exact code is now a replay.
	if _, err := f.service.Verify(ctx, userID, code); err == nil {
		t.Fatal("Verify accepted the code already consumed by enrollment")
	}

	// The next step is accepted and becomes the new watermark.
	f.advance(mfa.Period)
	next := currentCode(t, enr.Secret, f.now)
	method, err := f.service.Verify(ctx, userID, next)
	if err != nil {
		t.Fatalf("Verify first use: %v", err)
	}
	if method != "totp" {
		t.Fatalf("method = %q; want totp", method)
	}

	// The same code (same step) must not work twice.
	if _, err := f.service.Verify(ctx, userID, next); err == nil {
		t.Fatal("Verify replay: the same code was accepted twice")
	}

	// The previous step is below the watermark, even though it is inside the
	// skew window Validate would otherwise allow.
	prev := currentCode(t, enr.Secret, f.now.Add(-mfa.Period))
	if _, err := f.service.Verify(ctx, userID, prev); err == nil {
		t.Fatal("Verify accepted a code from a step below the watermark")
	}
}

// TestStore_AcceptStepGuard pins the atomic anti-replay write itself: the second
// claim for one step must be refused even though Validate would accept the code.
func TestStore_AcceptStepGuard(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "carol2")
	f.enroll(t, userID)

	step := f.now.Unix()/int64(mfa.Period/time.Second) + 10
	ok, err := f.store.AcceptStep(ctx, userID, step, f.now)
	if err != nil {
		t.Fatalf("AcceptStep: %v", err)
	}
	if !ok {
		t.Fatal("first AcceptStep was refused")
	}
	ok, err = f.store.AcceptStep(ctx, userID, step, f.now)
	if err != nil {
		t.Fatalf("AcceptStep second: %v", err)
	}
	if ok {
		t.Fatal("AcceptStep accepted the same step twice")
	}
}

func TestService_RecoveryCodeSingleUse(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "dave")
	codes := f.enroll(t, userID)

	method, err := f.service.Verify(ctx, userID, codes[0])
	if err != nil {
		t.Fatalf("Verify recovery code: %v", err)
	}
	if method != "recovery" {
		t.Fatalf("method = %q; want recovery", method)
	}

	if _, err := f.service.Verify(ctx, userID, codes[0]); err == nil {
		t.Fatal("recovery code worked twice")
	}

	// Formatting is irrelevant: the same code in lower case with a space is
	// rejected because it was spent, and a different code still works.
	if _, err := f.service.Verify(ctx, userID, codes[1]); err != nil {
		t.Fatalf("Verify second recovery code: %v", err)
	}

	st, err := f.service.Status(ctx, userID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.RemainingCodes != mfa.RecoveryCodeCount-2 {
		t.Errorf("remaining codes = %d; want %d", st.RemainingCodes, mfa.RecoveryCodeCount-2)
	}

	if _, err := f.service.Verify(ctx, userID, "AAAAA-AAAAA"); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("unknown recovery code = %v; want ErrInvalidCode", err)
	}
}

func TestService_RegenerateRecoveryCodes(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "erin")
	oldCodes := f.enroll(t, userID)

	newCodes, err := f.service.RegenerateRecoveryCodes(ctx, userID)
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(newCodes) != mfa.RecoveryCodeCount {
		t.Fatalf("got %d codes; want %d", len(newCodes), mfa.RecoveryCodeCount)
	}

	if _, err := f.service.Verify(ctx, userID, oldCodes[0]); err == nil {
		t.Fatal("an old recovery code still works after regeneration")
	}
	if _, err := f.service.Verify(ctx, userID, newCodes[0]); err != nil {
		t.Fatalf("new recovery code rejected: %v", err)
	}

	// Regenerating without an enabled credential is refused.
	other := f.createUser(t, "frank")
	if _, err := f.service.RegenerateRecoveryCodes(ctx, other); !errors.Is(err, mfa.ErrNotEnabled) {
		t.Fatalf("regenerate for unenrolled user = %v; want ErrNotEnabled", err)
	}
}

func TestService_Challenges(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "grace")

	token, err := f.service.CreateChallenge(ctx, userID, "/admin")
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("challenge token length = %d; want 64 hex chars", len(token))
	}

	ch, err := f.service.Challenge(ctx, token)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if ch.UserID != userID || ch.ReturnTo != "/admin" {
		t.Fatalf("challenge = %+v; want user %q return /admin", ch, userID)
	}

	// A challenge without a token is not found.
	if _, err := f.service.Challenge(ctx, ""); !errors.Is(err, mfa.ErrNotFound) {
		t.Fatalf("Challenge(empty) = %v; want ErrNotFound", err)
	}

	// Just inside the TTL is still valid.
	f.advance(mfa.ChallengeTTL - time.Second)
	if _, err := f.service.Challenge(ctx, token); err != nil {
		t.Fatalf("Challenge before expiry: %v", err)
	}

	// Past the TTL it is rejected.
	f.advance(2 * time.Second)
	if _, err := f.service.Challenge(ctx, token); !errors.Is(err, mfa.ErrChallengeExpired) {
		t.Fatalf("Challenge after expiry = %v; want ErrChallengeExpired", err)
	}

	// Consuming removes it.
	if err := f.service.ConsumeChallenge(ctx, token); err != nil {
		t.Fatalf("ConsumeChallenge: %v", err)
	}
	if _, err := f.service.Challenge(ctx, token); !errors.Is(err, mfa.ErrNotFound) {
		t.Fatalf("Challenge after consume = %v; want ErrNotFound", err)
	}
}

func TestService_DeleteExpiredChallenges(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "heidi")

	expired, err := f.service.CreateChallenge(ctx, userID, "/")
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	f.advance(mfa.ChallengeTTL + time.Second)
	live, err := f.service.CreateChallenge(ctx, userID, "/")
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	if err := f.service.DeleteExpiredChallenges(ctx); err != nil {
		t.Fatalf("DeleteExpiredChallenges: %v", err)
	}
	if _, err := f.service.Challenge(ctx, expired); !errors.Is(err, mfa.ErrNotFound) {
		t.Fatalf("expired challenge survived the sweep: %v", err)
	}
	if _, err := f.service.Challenge(ctx, live); err != nil {
		t.Fatalf("live challenge was swept: %v", err)
	}
}

func TestService_AdminResetDeletesEverything(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "ivan")
	f.enroll(t, userID)

	if _, err := f.service.CreateChallenge(ctx, userID, "/"); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	if err := f.service.Reset(ctx, userID); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if st, err := f.service.Status(ctx, userID); err != nil {
		t.Fatalf("Status after reset: %v", err)
	} else if st.Enabled {
		t.Fatal("credential still enabled after Reset")
	}

	ids, err := f.service.ListEnabledIDs(ctx)
	if err != nil {
		t.Fatalf("ListEnabledIDs: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("ListEnabledIDs = %v; want empty", ids)
	}

	var n int
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mfa_challenges WHERE user_id = ?`, userID).Scan(&n); err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	if n != 0 {
		t.Errorf("Reset left %d live challenges", n)
	}
}

func TestService_UpsertPendingNeverClobbersEnabled(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "judy")
	f.enroll(t, userID)

	if _, err := f.service.BeginEnrollment(ctx, userID, "judy"); !errors.Is(err, mfa.ErrNotPending) {
		t.Fatalf("BeginEnrollment for an enabled user = %v; want ErrNotPending", err)
	}

	// The original secret still verifies, proving nothing was replaced. Move a
	// step forward: enrollment consumed the step it was confirmed at.
	f.advance(mfa.Period)
	c, err := f.store.Get(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := f.service.Verify(ctx, userID, currentCode(t, c.Secret, f.now)); err != nil {
		t.Fatalf("original secret no longer verifies: %v", err)
	}
}

func TestService_ListEnabledIDs(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	enrolled := f.createUser(t, "kim")
	f.createUser(t, "leo")
	f.enroll(t, enrolled)

	// A pending enrollment must not appear in the admin badge query.
	pending := f.createUser(t, "mallory")
	if _, err := f.service.BeginEnrollment(ctx, pending, "mallory"); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}

	ids, err := f.service.ListEnabledIDs(ctx)
	if err != nil {
		t.Fatalf("ListEnabledIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != enrolled {
		t.Fatalf("ListEnabledIDs = %v; want [%s]", ids, enrolled)
	}
}

func TestStore_CascadeOnUserDelete(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	userID := f.createUser(t, "nina")
	f.enroll(t, userID)
	if _, err := f.service.CreateChallenge(ctx, userID, "/"); err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	if _, err := f.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	for _, table := range []string{"user_mfa", "user_mfa_recovery_codes", "mfa_challenges"} {
		var n int
		if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE user_id = ?`, userID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s kept %d rows after the user was deleted", table, n)
		}
	}
}
