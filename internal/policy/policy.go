// Package policy evaluates a per-app access policy.
//
// It is pure: no database, no HTTP, no globals. Callers assemble an Input from
// the app's stored policy fields, the user's effective assignments, the client
// address and a clock, then act on the returned Decision. Parsing uses the
// standard library only (net/netip for CIDRs) so the rules are testable in
// isolation and behave identically in forward-auth and OAuth authorize.
//
// Empty fields mean "no restriction". An app with no policy stored always
// allows, which is what keeps apps registered before this feature unchanged.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Denial reason tokens. They are short, stable and free of user data: they are
// logged and recorded in the authentication event so an operator can tell why
// access was refused without the response body leaking anything.
const (
	ReasonAdminOnly = "admin_only"
	ReasonGroup     = "group"
	ReasonRole      = "role"
	ReasonClientIP  = "client_ip"
	ReasonHours     = "hours"
	ReasonDays      = "days"
)

// Policy is the set of restrictions stored on an app. Zero value = allow all.
type Policy struct {
	// RequiredGroup is one app-scoped group name the user must hold
	// (directly or through a role). Matched case-insensitively.
	RequiredGroup string
	// RequiredRole is one app-scoped role name the user must hold.
	RequiredRole string
	// AllowedCIDRs is a comma or whitespace separated list of CIDR prefixes.
	AllowedCIDRs string
	// AdminOnly restricts the app to admin users.
	AdminOnly bool
	// AllowedHours is an "HH:MM-HH:MM" window in server local time. The window
	// may wrap past midnight (e.g. 22:00-06:00); equal endpoints mean all day.
	AllowedHours string
	// AllowedDays is a comma separated list of ISO weekdays (1 = Monday …
	// 7 = Sunday) with ranges allowed (e.g. "1-5,7").
	AllowedDays string
}

// IsEmpty reports whether the policy imposes no restriction at all.
func (p Policy) IsEmpty() bool {
	return strings.TrimSpace(p.RequiredGroup) == "" &&
		strings.TrimSpace(p.RequiredRole) == "" &&
		strings.TrimSpace(p.AllowedCIDRs) == "" &&
		strings.TrimSpace(p.AllowedHours) == "" &&
		strings.TrimSpace(p.AllowedDays) == "" &&
		!p.AdminOnly
}

// Input is everything Evaluate needs: the policy and the facts about this
// request. UserGroups and UserRoles are the user's effective names for the app
// (the same sets embedded in OIDC claims).
type Input struct {
	Policy

	UserGroups []string
	UserRoles  []string
	IsAdmin    bool
	// ClientIP is a bare address (no port), IPv4 or IPv6.
	ClientIP string
	// Now is the wall clock the hours/days rules are evaluated against.
	Now time.Time
	// Location is the timezone for Now. Nil means time.Local, matching the
	// server local time the admin entered the window in.
	Location *time.Location
}

// Decision is the outcome of Evaluate.
type Decision struct {
	Allowed bool
	// Reason is one of the Reason* tokens when Allowed is false, and empty
	// when the policy allowed the request.
	Reason string
}

// Allow reports an explicit allow.
func Allow() Decision { return Decision{Allowed: true} }

// Deny reports a denial for the given reason token.
func Deny(reason string) Decision { return Decision{Allowed: false, Reason: reason} }

// Evaluate applies the policy to the input. Every configured restriction must
// pass — they combine with AND, and an admin is not exempt from any of them
// (admin_only additionally requires admin). An error means a rule could not be
// evaluated (malformed stored value or unparseable client address); callers
// must treat an error as a denial and never serve the request.
func Evaluate(in Input) (Decision, error) {
	if in.Policy.IsEmpty() {
		return Allow(), nil
	}

	if in.Policy.AdminOnly && !in.IsAdmin {
		return Deny(ReasonAdminOnly), nil
	}

	if want := strings.TrimSpace(in.Policy.RequiredGroup); want != "" {
		if !containsName(in.UserGroups, want) {
			return Deny(ReasonGroup), nil
		}
	}

	if want := strings.TrimSpace(in.Policy.RequiredRole); want != "" {
		if !containsName(in.UserRoles, want) {
			return Deny(ReasonRole), nil
		}
	}

	if strings.TrimSpace(in.Policy.AllowedCIDRs) != "" {
		allowed, err := clientIPAllowed(in.Policy.AllowedCIDRs, in.ClientIP)
		if err != nil {
			return Decision{}, err
		}
		if !allowed {
			return Deny(ReasonClientIP), nil
		}
	}

	loc := in.Location
	if loc == nil {
		loc = time.Local
	}
	now := in.Now.In(loc)

	if strings.TrimSpace(in.Policy.AllowedDays) != "" {
		days, err := parseDays(in.Policy.AllowedDays)
		if err != nil {
			return Decision{}, err
		}
		if !days[isoWeekday(now.Weekday())] {
			return Deny(ReasonDays), nil
		}
	}

	if strings.TrimSpace(in.Policy.AllowedHours) != "" {
		start, end, err := parseHours(in.Policy.AllowedHours)
		if err != nil {
			return Decision{}, err
		}
		minutes := now.Hour()*60 + now.Minute()
		if !withinWindow(minutes, start, end) {
			return Deny(ReasonHours), nil
		}
	}

	return Allow(), nil
}

// Validate checks that every non-empty policy field is well formed. It exists
// so the admin form can reject garbage at save time; Evaluate repeats the same
// parsing and fails closed, because a value could predate validation.
func Validate(p Policy) error {
	var errs []error
	if strings.TrimSpace(p.AllowedCIDRs) != "" {
		if _, err := parseCIDRs(p.AllowedCIDRs); err != nil {
			errs = append(errs, err)
		}
	}
	if strings.TrimSpace(p.AllowedHours) != "" {
		if _, _, err := parseHours(p.AllowedHours); err != nil {
			errs = append(errs, err)
		}
	}
	if strings.TrimSpace(p.AllowedDays) != "" {
		if _, err := parseDays(p.AllowedDays); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// containsName reports whether list holds want, ignoring case and surrounding
// whitespace.
func containsName(list []string, want string) bool {
	for _, got := range list {
		if strings.EqualFold(strings.TrimSpace(got), want) {
			return true
		}
	}
	return false
}

// clientIPAllowed reports whether ip falls inside any prefix in list.
func clientIPAllowed(list, ip string) (bool, error) {
	prefixes, err := parseCIDRs(list)
	if err != nil {
		return false, err
	}

	addr, err := parseAddr(ip)
	if err != nil {
		return false, err
	}

	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}

// parseAddr parses a bare IP address, tolerating an accidental "ip:port" form
// so a caller that forgot to strip the port still produces a usable decision.
func parseAddr(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, errors.New("policy: client address is empty")
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.Unmap(), nil
	}
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		return addrPort.Addr().Unmap(), nil
	}
	return netip.Addr{}, fmt.Errorf("policy: client address %q is not an IP address", raw)
}

// parseCIDRs parses a comma or whitespace separated prefix list.
func parseCIDRs(raw string) ([]netip.Prefix, error) {
	tokens := splitList(raw)
	if len(tokens) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(tokens))
	for _, tok := range tokens {
		prefix, err := netip.ParsePrefix(tok)
		if err != nil {
			return nil, fmt.Errorf("policy: allowed cidrs: %q is not a CIDR prefix (for example 192.0.2.0/24 or 2001:db8::/32)", tok)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// parseHours parses an "HH:MM-HH:MM" window and returns start and end as
// minutes since midnight. Both endpoints are inclusive; when start equals end
// the window covers the whole day. start > end wraps past midnight.
func parseHours(raw string) (start, end int, err error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("policy: allowed hours: %q is not an HH:MM-HH:MM window", raw)
	}
	start, err = parseClock(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("policy: allowed hours: %q is not an HH:MM-HH:MM window", raw)
	}
	end, err = parseClock(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("policy: allowed hours: %q is not an HH:MM-HH:MM window", raw)
	}
	return start, end, nil
}

// parseClock parses "HH:MM" into minutes since midnight.
func parseClock(s string) (int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, errors.New("clock must be HH:MM")
	}
	hh, err := strconv.Atoi(s[:2])
	if err != nil {
		return 0, fmt.Errorf("hour: %w", err)
	}
	mm, err := strconv.Atoi(s[3:])
	if err != nil {
		return 0, fmt.Errorf("minute: %w", err)
	}
	if hh < 0 || hh > 23 {
		return 0, fmt.Errorf("hour %d out of range", hh)
	}
	if mm < 0 || mm > 59 {
		return 0, fmt.Errorf("minute %d out of range", mm)
	}
	return hh*60 + mm, nil
}

// withinWindow reports whether minutes falls inside [start, end], wrapping when
// start is later than end. Equal endpoints mean the whole day.
func withinWindow(minutes, start, end int) bool {
	if start == end {
		return true
	}
	if start < end {
		return minutes >= start && minutes <= end
	}
	return minutes >= start || minutes <= end
}

// parseDays parses an ISO weekday list with ranges, e.g. "1-5,7".
func parseDays(raw string) (map[int]bool, error) {
	tokens := splitList(raw)
	if len(tokens) == 0 {
		return nil, nil
	}
	days := make(map[int]bool, 7)
	for _, tok := range tokens {
		if strings.Contains(tok, "-") {
			parts := strings.Split(tok, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("policy: allowed days: %q is not an ISO weekday list (1-7, ranges like 1-5)", tok)
			}
			first, errFirst := parseWeekday(parts[0])
			last, errLast := parseWeekday(parts[1])
			if errFirst != nil || errLast != nil || first > last {
				return nil, fmt.Errorf("policy: allowed days: %q is not an ISO weekday range (ascending, 1-7)", tok)
			}
			for d := first; d <= last; d++ {
				days[d] = true
			}
			continue
		}
		day, err := parseWeekday(tok)
		if err != nil {
			return nil, fmt.Errorf("policy: allowed days: %q is not an ISO weekday list (1-7, ranges like 1-5)", tok)
		}
		days[day] = true
	}
	return days, nil
}

// parseWeekday parses one ISO weekday number (1 = Monday … 7 = Sunday).
func parseWeekday(s string) (int, error) {
	day, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("weekday: %w", err)
	}
	if day < 1 || day > 7 {
		return 0, fmt.Errorf("weekday %d out of range", day)
	}
	return day, nil
}

// isoWeekday converts a time.Weekday (Sunday = 0) to an ISO weekday (Monday =
// 1 … Sunday = 7).
func isoWeekday(wd time.Weekday) int {
	if wd == time.Sunday {
		return 7
	}
	return int(wd)
}

// splitList splits on commas and any whitespace, dropping empty tokens.
func splitList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}
