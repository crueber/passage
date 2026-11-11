# OIDC signing-key rotation

Passage signs OIDC `id_token`s with RS256. Every signing key has a **kid** (key
ID) in the JWT header, and the public halves are published at
`/.well-known/jwks.json`. Relying parties select the verification key by kid,
which is what makes key rotation possible without reissuing tokens.

Before this feature Passage had exactly one RSA key, stored as a PEM in the
`oidc_config` table under `rsa_private_key`. The new code never writes that row.
It reads it once at startup to import the key into the keyring, and leaves it in
place as the rollback path for an older binary.

## Schema

`internal/db/migrations/023_oauth_signing_keys.sql`:

```sql
CREATE TABLE oauth_signing_keys (
    kid             TEXT PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at      DATETIME
);
```

The kid is never computed in SQL. It is the base64url SHA-256 of the public
key's DER encoding, derived in Go (`deriveKID`), the same derivation earlier
versions used. Importing the legacy key therefore keeps its kid, so existing
`id_token`s keep verifying and clients see no JWKS change.

## Keyring semantics

* **Signing** uses the newest non-retired key.
* **The JWKS serves every non-retired key**, each with its own kid.
* **Verification** (including the logout `id_token_hint`) selects the key by the
  token's kid and accepts any non-retired key. A missing, unknown, or retired
  kid is rejected.
* **Rotate** generates a new 2048-bit RSA key and makes it current. It does not
  retire the previous key: old `id_token`s must keep verifying until they
  expire.
* **Retire** stops a key being served and accepted. The last non-retired key
  cannot be retired — rotate first — so the issuer can always sign.
* **Delete** removes a retired key permanently. Active keys cannot be deleted.
* Nothing is ever retired or deleted automatically. History is the point.

Rotations do not affect browser sessions, access tokens, or refresh tokens:
those are opaque random values looked up in SQLite, not JWTs.

## Startup

`oauth.EnsureSigningKeys` runs once at startup (and again from
`oauth.NewService`) and is idempotent:

1. If `oauth_signing_keys` has any row, do nothing.
2. Otherwise import the legacy `oidc_config.rsa_private_key` PEM with its
   derived kid, preserving the legacy `created_at`.
3. Otherwise generate a new key.

There is no key-management configuration and no key file on disk: keys live in
the database like every other secret Passage stores.

## Admin UI

**Admin → Signing keys** (`/admin/signing-keys`, System section) lists every key
with its kid, creation time, and state (`Current`, `Active`, `Retired`):

* **Rotate key** generates a new key and makes it current.
* **Retire** is offered for any active key except the only remaining one.
* **Delete** is offered for retired keys only.

All three are POSTs with a CSRF token and a confirmation, and are recorded in
the admin audit log as `oauth.key_rotate`, `oauth.key_retire`, and
`oauth.key_delete`. Private key material is never rendered or logged.

## Operational guidance

Retire an old key only after the longest id_token lifetime has passed (one hour
with the current `idTokenTTL`), so no client is still holding a token signed by
it. If a key is suspected compromised, rotate first and retire the suspect key
immediately: id_tokens it signed stop verifying at once, and affected relying
parties will force a new sign-in, which is the desired outcome.

Deleting a retired key is housekeeping, not security: retirement already
removed it from the JWKS and from verification.
