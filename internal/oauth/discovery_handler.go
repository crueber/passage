package oauth

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
)

// Discovery returns the OpenID Connect discovery document.
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                        h.baseURL,
		"authorization_endpoint":                        h.baseURL + "/oauth/authorize",
		"token_endpoint":                                h.baseURL + "/oauth/token",
		"userinfo_endpoint":                             h.baseURL + "/oauth/userinfo",
		"end_session_endpoint":                          h.baseURL + "/oauth/logout",
		"revocation_endpoint":                           h.baseURL + "/oauth/revoke",
		"introspection_endpoint":                        h.baseURL + "/oauth/introspect",
		"jwks_uri":                                      h.baseURL + "/.well-known/jwks.json",
		"response_types_supported":                      []string{"code"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"scopes_supported":                              ServerScopes(),
		"token_endpoint_auth_methods_supported":         []string{"client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_post", "client_secret_basic"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token"},
		"claims_supported":                              []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "email_verified", "preferred_username", "roles", "groups"},
		"nonce_supported":                               true,
		"code_challenge_methods_supported":              []string{"S256"},
	}

	h.writeJSON(w, http.StatusOK, doc)
}

// JWKS returns the JSON Web Key Set of every non-retired signing key. Each key
// carries its own kid, so a client can verify an id_token signed before a
// rotation by selecting the matching entry.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	keys := h.svc.ActiveSigningKeys()
	if len(keys) == 0 {
		// Startup guarantees at least one key and the last key cannot be
		// retired, so this is a broken invariant, not a normal state.
		h.logger.Error("oauth: JWKS requested with no active signing key")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	jwks := map[string]any{
		"keys": jwksFor(keys),
	}

	h.writeJSON(w, http.StatusOK, jwks)
}

// jwksFor renders signing keys as RFC 7517 JWK entries.
func jwksFor(keys []*SigningKey) []map[string]any {
	jwks := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		pub := key.PublicKey()
		if pub == nil {
			continue
		}

		// Encode the modulus (n) as base64url with no padding.
		nEncoded := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())

		// Encode the exponent (e) as big-endian bytes then base64url.
		// e is typically 65537 (0x010001), which fits in 3 bytes.
		eBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(eBuf, uint32(pub.E)) //nolint:gosec // e fits in uint32
		// Trim leading zero bytes.
		i := 0
		for i < len(eBuf)-1 && eBuf[i] == 0 {
			i++
		}
		eEncoded := base64.RawURLEncoding.EncodeToString(eBuf[i:])

		jwks = append(jwks, map[string]any{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": key.KID,
			"n":   nEncoded,
			"e":   eEncoded,
		})
	}
	return jwks
}
