# Upstream identity providers (OIDC/OAuth)

Passage can sign users in through an external OIDC/OAuth provider (Authentik,
Keycloak, Authelia, Google, Entra ID, and so on) and link the external identity
to a local account. A configured provider adds one button to the login page.

With no provider configured the feature is completely inert: the two routes
exist but resolve no provider, and every other flow behaves exactly as before.

## Configuration

```yaml
auth:
  providers:
    - name: "authentik"
      label: "Authentik"
      issuer: "https://auth.example.com/application/o/passage/"
      client_id: "passage"
      client_secret: "changeme"
      scopes: ["openid", "email", "profile"]
      auto_create: false
```

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique URL slug, `[a-z0-9][a-z0-9_-]*`, max 64 characters. Appears in the sign-in URLs, so changing it breaks in-flight flows and existing links (links are keyed by it). |
| `label` | no | Login button text. Defaults to `name`. |
| `issuer` | yes | Absolute `https` URL. Passage fetches `<issuer>/.well-known/openid-configuration` and requires the document's `issuer` to match exactly (a trailing slash is ignored). |
| `client_id` | yes | OAuth client id. |
| `client_secret` | yes | OAuth client secret. Sent with HTTP Basic auth (`client_secret_basic`) to the token endpoint. |
| `scopes` | no | Defaults to `openid email profile` and must include `openid`. `email` is needed for email-based linking. |
| `auto_create` | no | Create a local account on first sign-in when no link or matching email exists. Always subject to the global registration policy. |

There is deliberately **no environment-variable override** for the list: a list
has no useful single-value env form. Configure it in `passage.yaml`.

`server.base_url` is required when any provider is configured: it builds the
registered redirect URI.

Register this redirect URI with the provider:

```
<server.base_url>/login/oidc/<name>/callback
```

## Routes

Both are public `GET`s (no CSRF token; the flow is bound by state, nonce, and
PKCE instead).

| Route | Purpose |
|---|---|
| `GET /login/oidc/{provider}/start` | Builds the authorization request and redirects upstream. Accepts the same `rd` return path as the other login methods. |
| `GET /login/oidc/{provider}/callback` | Validates state, exchanges the code, verifies the id_token, links or creates the account, creates a session. |

## Flow and security properties

1. **Start** discovers the provider, generates 32 random bytes each for
   `state`, `nonce`, and the PKCE `code_verifier` with `crypto/rand`, and stores
   them in a short-lived (10 minute) HttpOnly, `SameSite=Lax`, `Path=/` cookie.
   The cookie is provider-bound, and its name is scoped per provider, so two
   sign-ins started in different tabs do not overwrite each other's flow. The
   PKCE challenge is S256.
2. **Callback** clears the cookie unconditionally (single use), then checks
   that the cookie exists, has not expired, names the same provider, and that
   its `state` equals the query `state` using `crypto/subtle`.
3. The code is exchanged at the provider's token endpoint with the PKCE
   verifier and `client_secret_basic`.
4. The `id_token` signature is verified against the provider's JWKS. **RS256
   only.** `iss`, `aud`, `exp` (required), and `nonce` are checked. Discovery
   and JWKS documents are cached; an unknown `kid` triggers one cache refresh
   before the login is rejected.
5. On any failure the browser goes back to `/login` with a flash message and an
   `idp.failure` authentication event is recorded. No token, authorization
   code, or claim value is ever logged. A successful sign-in records
   `idp.login` (not `login.success`) with the provider slug as the detail.

Discovery and the JWKS/token endpoints must be absolute `https` URLs; a
discovery document that names a different issuer is rejected.

## Account linking

Every external sign-in resolves a local account in this order:

1. **Existing link** — a row in `idp_links` for `(provider, subject)`. The
   account must be active. This is the normal path after the first sign-in and
   does not depend on email at all.
2. **Verified email** — if the provider asserts `email_verified: true` and a
   local account has that email address, the identity is linked to it and the
   user signs in. An unverified email can never link.
3. **Create** — only when the provider sets `auto_create: true` *and* the
   global registration policy allows registration. The username comes from
   `preferred_username`, then the email local part, sanitised and made unique.
   The account has **no password**, and `email_verified` is copied from the
   provider.

Anything else is refused with a flash on `/login` (`No account is linked to
that identity`). An inactive linked account is refused with the usual
`account-inactive` flash.

Only configure providers you trust to assert `email_verified` honestly: that
claim is what allows an upstream identity to attach to an existing local
account.

Deleting a user removes their links (`ON DELETE CASCADE`).

## Second factor

An external sign-in is a primary authentication method, like a passkey or a
magic link. Passage does **not** add an MFA challenge to it: the provider has
already authenticated the user, and linking is gated on a pre-existing link or
a verified email. MFA enforcement remains on the password flow only.

If an operator needs MFA for an account, the account's password flow is where
it applies; the external provider is responsible for its own MFA policy.

## Local accounts created by a provider

- `password_hash` stays empty, so password login for that account always fails.
  An admin can set a password (or the user can use "forgot password", if email
  works) if they want password login too.
- `email_verified` reflects the provider's claim at creation time. It is not
  re-synced on later sign-ins.
- Roles, groups, and admin flags are not taken from the provider; manage them
  in Passage.

## Troubleshooting

- **`invalid_redirect_uri`** — the URI registered with the provider must be
  exactly `<server.base_url>/login/oidc/<name>/callback`.
- **`id_token verification failed`** — check the provider's issuer URL, the
  client id used as the audience, and that the provider signs with RS256. The
  `iss` claim must equal the configured `issuer` byte for byte, including a
  trailing slash if the provider emits one (discovery tolerates a trailing
  slash, the `iss` comparison does not).
- **No sign-in button** — the provider list is empty or configuration failed
  validation. `cfg.Validate` reports every provider problem at once at startup.
