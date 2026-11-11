# JWT access tokens, resource indicators, and the per-app scope registry

Passage's OAuth 2.0 / OIDC provider issues **signed JWT access tokens**
(RS256, the same keyring and `kid` that signs id_tokens and is published at
`/.well-known/jwks.json`). Refresh tokens are still opaque, single-use rows and
id_tokens are unchanged.

This document covers the token shape, the per-app scope and audience
registries, RFC 8707 resource indicators, and how revocation works now that an
access token is stateless.

## Access token format

```json
{
  "iss": "https://auth.example.com",
  "sub": "<user id>",
  "aud": ["https://api.example.com"],
  "exp": 1760003600,
  "iat": 1760000000,
  "jti": "<32 random bytes, hex>",
  "scope": "openid profile",
  "client_id": "<client id>"
}
```

- `aud` is the granted **resource** when the client requested one, otherwise the
  client id (the pre-registry behaviour).
- The lifetime is unchanged: one hour. `expires_in` in the token response is
  still `3600`.
- The header carries `kid`, so a client verifies the token with the matching
  entry in the JWKS. Only RS256 is accepted for verification; `alg: none` and
  HMAC algorithms are rejected.
- `jti` is what makes the otherwise stateless token revocable (see below).
- The token is **not** stored in `oauth_tokens`. The `oauth_tokens` table is
  still read, so tokens issued before this change keep working (see
  "Compatibility").

## Scope registry (`apps.scopes`)

One scope per line in the admin app form ("Allowed scopes"). Empty means
"no registry": any scope the client asks for is granted, exactly as before.

When the registry is non-empty:

- the requested scopes must be a **subset** of it; anything else is refused at
  `/oauth/authorize` with `invalid_scope` and no code is issued;
- the same check runs again at the token endpoint, so tightening the registry
  also invalidates codes that were already issued;
- `openid` must be registered if clients may ask for an id_token. A registry
  without `openid` makes an `openid` request `invalid_scope`;
- the granted scope is normalised (whitespace collapsed, duplicates dropped)
  and echoed in the token response and in the `scope` claim.

On the `refresh_token` grant, the optional `scope` parameter may **narrow** the
grant but never widen it (RFC 6749 §6); a wider value is `invalid_scope`.

Scope values are validated on save: `[A-Za-z0-9._:-]+`. Duplicates are
rejected.

Discovery advertises the server's own vocabulary, `openid profile email`
(`oauth.ServerScopes()`). App-specific scopes are not advertised globally because
the registry is per client.

## Resource indicators (`apps.resources`, RFC 8707)

One absolute URI per line in the admin app form ("Allowed resources
(audiences)"). Empty means resource indicators are **not accepted**.

- `resource` is accepted on `/oauth/authorize` and `/oauth/token`
  (`authorization_code` and `refresh_token` grants).
- The value must exactly match a registered entry. A configured-but-unmatched
  resource, a resource sent to a client with no registry, or a value that is not
  an absolute URI without a fragment is `invalid_target` (400). No code or token
  is issued.
- The granted resource is stored with the authorization code, so the token
  endpoint issues a token for the audience the user approved. A token request
  that echoes a *different* resource is `invalid_target`.
- Exactly one `resource` parameter is supported (a Passage access token has one
  audience). Sending more than one is `invalid_target`.
- A refresh token does not persist the original resource, so the client should
  resend `resource` on each refresh to keep the resource audience; without it
  the new access token's audience is the client id.

Entry validation: absolute URI (scheme required), no fragment, no duplicates.

## Revocation

`POST /oauth/revoke` keeps its RFC 7009 contract: authenticated clients only,
`200` for unknown or foreign tokens, and no information about token state.

- Opaque access tokens and refresh tokens are handled as before (row delete /
  whole rotation family delete).
- A JWT access token is **denylisted by `jti`** in `oauth_revoked_jti`, with its
  `exp`. `ValidateAccessToken`, `/oauth/userinfo`, and `/oauth/introspect` all
  consult the denylist, so a revoked token is inactive everywhere immediately.
- `oauth_revoked_jti` rows are removed by the existing hourly OAuth cleanup
  (`SQLiteStore.DeleteExpired`) once `expires_at` has passed; after that the
  signature and `exp` checks reject the token anyway.

## Compatibility

`ValidateAccessToken` and introspection detect a JWT by its compact-JWS shape
(three dot-separated segments). Anything else takes the database path into
`oauth_tokens`. As a result:

- tokens issued before this change keep validating and introspecting until they
  expire — nobody is forced to sign in again on upgrade;
- introspection reports the same fields for both shapes, with `aud` set to the
  resource or the client id and `token_type` `Bearer`.

## Schema (migration `024_oauth_scopes.sql`)

Additive only:

| Change | Meaning |
|---|---|
| `apps.scopes TEXT NOT NULL DEFAULT ''` | newline-separated scope registry |
| `apps.resources TEXT NOT NULL DEFAULT ''` | newline-separated audience registry |
| `oauth_codes.resource TEXT NOT NULL DEFAULT ''` | resource granted at authorize time |
| `oauth_revoked_jti(jti TEXT PRIMARY KEY, expires_at DATETIME NOT NULL, revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)` | JWT revocation denylist |

Every default is "behaves like before": an upgraded database with no admin
changes issues the same tokens it did previously (opaque token behaviour is
replaced by a JWT of the same lifetime and scope, audience = client id).

## Admin UI

The app edit form's OAuth section has two textareas, in the same style as
Redirect URIs:

- **Allowed scopes** — one per line; blank means unrestricted.
- **Allowed resources (audiences)** — one per line, absolute URIs; blank means
  resource indicators are refused.

Both are validated on save with the standard form error flash; an invalid value
re-renders the form and changes nothing.
