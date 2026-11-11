package oauth

import (
	"fmt"
	"strings"

	"github.com/crueber/passage/internal/app"
)

// serverScopes is the scope vocabulary Passage itself understands. It is
// advertised in the discovery document. An app's own registry (apps.scopes)
// may name any additional scopes, but these are the only ones with defined
// behaviour: openid triggers OIDC claims, profile and email select the user
// claims returned by userinfo and the id_token.
var serverScopes = []string{"openid", "profile", "email"}

// ServerScopes returns a copy of the scope vocabulary the server advertises.
// The copy keeps a caller from mutating the package's list.
func ServerScopes() []string {
	return append([]string(nil), serverScopes...)
}

// normalizeScope returns the canonical space-delimited form of a scope value:
// whitespace collapsed, duplicates dropped, first-seen order preserved. A
// client that repeats a scope gets it once in the granted scope and the token.
func normalizeScope(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return strings.Join(out, " ")
}

// scopeValues splits a normalized scope string into its values.
func scopeValues(scope string) []string {
	return strings.Fields(scope)
}

// scopeSubset reports whether every value in requested appears in parent.
func scopeSubset(requested, parent string) bool {
	allowed := make(map[string]bool, len(scopeValues(parent)))
	for _, s := range scopeValues(parent) {
		allowed[s] = true
	}
	for _, s := range scopeValues(requested) {
		if !allowed[s] {
			return false
		}
	}
	return true
}

// validateRequestedScopes enforces an app's scope registry. An empty registry
// means "no registry": the client may ask for anything, which is the behaviour
// before the registry existed. With a registry configured, the request must be
// a subset of it, and asking for an id_token (scope openid) requires openid to
// be registered.
//
// The returned error wraps ErrInvalidScope and names the offending scope. A
// scope name is client-supplied vocabulary, not secret material.
func validateRequestedScopes(registry []string, requested string) error {
	if len(registry) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(registry))
	for _, s := range registry {
		allowed[strings.TrimSpace(s)] = true
	}

	requestedValues := scopeValues(normalizeScope(requested))
	for _, s := range requestedValues {
		if !allowed[s] {
			return fmt.Errorf("%w: %q is not registered for this client", ErrInvalidScope, s)
		}
	}
	// Including openid asks for an id_token, and the subset rule above already
	// requires it to be registered. Keeping openid in every registry that
	// expects OIDC clients is therefore load-bearing: a registry without it
	// turns an openid request into invalid_scope.
	return nil
}

// resolveResource validates an RFC 8707 resource indicator against the app's
// audience registry and returns the granted audience. An empty requested
// resource means the client did not ask for one (the audience is the client
// id). A non-empty value is accepted only when the registry lists it exactly:
// a configured-but-unmatched resource, or a resource sent to an app with no
// registry, is invalid_target so no token is issued for an unvalidated
// audience.
func resolveResource(a *app.App, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", nil
	}
	if err := app.ValidateResourceURI(requested); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}
	if len(a.AllowedResources) == 0 {
		return "", fmt.Errorf("%w: this client has no resource registry", ErrInvalidTarget)
	}
	for _, allowed := range a.AllowedResources {
		if strings.TrimSpace(allowed) == requested {
			return requested, nil
		}
	}
	return "", fmt.Errorf("%w: %q is not registered for this client", ErrInvalidTarget, requested)
}

// reconcileResource resolves the audience of a token exchange. The code
// carries the resource granted at authorization time; the token request may
// echo it, in which case it must match exactly. Either value is re-validated
// against the current registry, so removing a resource from an app also
// invalidates a code that was issued for it.
func reconcileResource(a *app.App, granted, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested != "" && requested != strings.TrimSpace(granted) {
		return "", fmt.Errorf("%w: resource does not match the authorization request", ErrInvalidTarget)
	}
	return resolveResource(a, granted)
}
