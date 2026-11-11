package app

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// scopeTokenPattern is the allowed shape of a scope value in an app's scope
// registry. It is deliberately narrow (RFC 6749 §3.3 permits a wider set) so a
// typo or a paste of a whole request line is rejected at save time instead of
// silently never matching a client request.
var scopeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// ValidateAllowedScopes checks an app's scope registry. Values are compared
// exactly, so duplicates are rejected rather than silently collapsed.
func ValidateAllowedScopes(scopes []string) error {
	var errs []error
	seen := make(map[string]bool, len(scopes))
	for _, raw := range scopes {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if !scopeTokenPattern.MatchString(scope) {
			errs = append(errs, fmt.Errorf("scope %q may only contain letters, digits, '.', '_', ':' and '-'", scope))
			continue
		}
		if seen[scope] {
			errs = append(errs, fmt.Errorf("scope %q is listed more than once", scope))
			continue
		}
		seen[scope] = true
	}
	return errors.Join(errs...)
}

// ValidateAllowedResources checks an app's audience registry (RFC 8707). Every
// entry must be an absolute URI without a fragment: the audience is compared
// exactly, so a relative value or one carrying a fragment could never be
// requested by a conforming client.
func ValidateAllowedResources(resources []string) error {
	var errs []error
	seen := make(map[string]bool, len(resources))
	for _, raw := range resources {
		resource := strings.TrimSpace(raw)
		if resource == "" {
			continue
		}
		if err := ValidateResourceURI(resource); err != nil {
			errs = append(errs, err)
			continue
		}
		if seen[resource] {
			errs = append(errs, fmt.Errorf("resource %q is listed more than once", resource))
			continue
		}
		seen[resource] = true
	}
	return errors.Join(errs...)
}

// ValidateResourceURI reports whether raw is an absolute URI without a
// fragment, the form RFC 8707 §2 requires of a resource indicator.
func ValidateResourceURI(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("resource %q is not a valid URI", raw)
	}
	if u.Scheme == "" {
		return fmt.Errorf("resource %q must be an absolute URI with a scheme", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("resource %q must not contain a fragment", raw)
	}
	return nil
}
