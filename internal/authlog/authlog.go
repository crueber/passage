// Package authlog records authentication events — logins, logouts, passkey and
// magic-link use, and their failures — for the admin security log.
//
// Recording is deliberately best-effort: a failure to write an event must never
// fail an authentication flow. See Recorder.Record.
package authlog

import "time"

// Event names. These are the single definition of truth shared by the emitters
// and the admin security-log page (via Names), so the filter cannot drift from
// what is actually recorded.
const (
	EventLoginSuccess      = "login.success"
	EventLoginFailure      = "login.failure"
	EventLoginThrottled    = "login.throttled"
	EventLogout            = "logout"
	EventPasskeyLogin      = "passkey.login"
	EventPasskeyFailure    = "passkey.failure"
	EventMagicLinkLogin    = "magiclink.login"
	EventMagicLinkFailure  = "magiclink.failure"
	EventRegisterSuccess   = "register.success"
	EventOAuthAuthorize    = "oauth.authorize"
	EventOAuthToken        = "oauth.token"
	EventOAuthTokenFailed  = "oauth.token_failure"
	EventOAuthRefreshReuse = "oauth.refresh_reuse"
	EventOAuthRevoke       = "oauth.revoke"
	EventOAuthLogout       = "oauth.logout"

	// Two-factor authentication. A challenge is issued after a correct password
	// when the account has TOTP enabled; it is not a login on its own. No event
	// ever carries a TOTP code, secret, or recovery code — Detail names the
	// method ("totp", "recovery") or the action, never the credential.
	EventMFAChallenge        = "mfa.challenge"
	EventMFASuccess          = "mfa.success"
	EventMFAFailure          = "mfa.failure"
	EventMFAEnrolled         = "mfa.enrolled"
	EventMFADisabled         = "mfa.disabled"
	EventMFACodesRegenerated = "mfa.codes_regenerated"
	EventMFAReset            = "mfa.reset"
)

// Outcomes describe how an event ended.
const (
	OutcomeSuccess   = "success"
	OutcomeFailure   = "failure"
	OutcomeThrottled = "throttled"
)

// Event is one authentication event.
//
// UserID and Username are recorded as plain strings with no foreign key to
// users: a failed login for an unknown username has no user row, and a deleted
// user must not take their login history with them.
type Event struct {
	ID        string
	Event     string
	Outcome   string
	UserID    string
	Username  string
	IP        string
	UserAgent string
	Detail    string
	CreatedAt time.Time
}

// Names returns the known event names, in display order, as a fresh slice.
func Names() []string {
	return []string{
		EventLoginSuccess,
		EventLoginFailure,
		EventLoginThrottled,
		EventLogout,
		EventPasskeyLogin,
		EventPasskeyFailure,
		EventMagicLinkLogin,
		EventMagicLinkFailure,
		EventRegisterSuccess,
		EventOAuthAuthorize,
		EventOAuthToken,
		EventOAuthTokenFailed,
		EventOAuthRefreshReuse,
		EventOAuthRevoke,
		EventOAuthLogout,
		EventMFAChallenge,
		EventMFASuccess,
		EventMFAFailure,
		EventMFAEnrolled,
		EventMFADisabled,
		EventMFACodesRegenerated,
		EventMFAReset,
	}
}

// Outcomes returns the known outcomes, in display order, as a fresh slice.
func Outcomes() []string {
	return []string{OutcomeSuccess, OutcomeFailure, OutcomeThrottled}
}

// IsKnownEvent reports whether name is one of the exported event names.
func IsKnownEvent(name string) bool {
	for _, n := range Names() {
		if n == name {
			return true
		}
	}
	return false
}

// IsKnownOutcome reports whether name is one of the exported outcome values.
func IsKnownOutcome(name string) bool {
	for _, n := range Outcomes() {
		if n == name {
			return true
		}
	}
	return false
}
