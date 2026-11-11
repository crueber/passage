# Passage Security Reference

This document covers the trust model, session cookie scope, known limitations, and operational security requirements for Passage deployments.

---

## Section 1 — Trust Model

Passage is a **forward-authentication proxy**, not an edge proxy. It sits behind a reverse proxy (Nginx, Traefik, Caddy) and is never directly exposed to the internet.

### Trust Boundary

The reverse proxy is trusted to forward the following headers accurately. Passage uses these headers to determine which downstream application is being accessed:

- `X-Original-URL`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

**`X-Passage-*` headers on incoming requests to Passage are NOT trusted.** Passage sets `X-Passage-User`, `X-Passage-Email`, and `X-Passage-Is-Admin` on outgoing responses to the reverse proxy. Any such headers arriving on an inbound request are ignored.

### Deployment Constraint

Passage must only listen on `127.0.0.1` or a private network interface. It must never be directly exposed to the internet. The reverse proxy and Passage must run on the same host or in the same trusted private network.

---

## Section 2 — Session Cookie Scope

The session cookie (`passage_session` by default, configurable via `PASSAGE_SESSION_COOKIE_NAME`) is scoped to the **Passage host only**. It is not sent to downstream applications.

Downstream apps receive identity via headers injected by the reverse proxy after Passage returns `200 OK` from `/auth/nginx` or `/auth/traefik`:

- `X-Passage-User` — the authenticated username
- `X-Passage-Email` — the authenticated user's email address
- `X-Passage-Is-Admin` — whether the user has admin privileges

### Cookie Attributes

| Attribute | Value |
|---|---|
| `HttpOnly` | `true` — not accessible to JavaScript |
| `Secure` | configurable — must be `true` in production |
| `SameSite` | `Lax` |

### CSRF Protection

`SameSite: Lax` provides partial CSRF protection for cross-origin top-level navigations, but browser behaviour is inconsistent. Full CSRF protection is provided by the **synchronizer token pattern**: an HMAC-signed `_csrf` token is embedded in every POST form and verified server-side. htmx requests may supply this value via the `HX-CSRF-Token` request header instead.

---

## Section 3 — Known Limitations

### 1. WebAuthn Requires HTTPS

The WebAuthn API is disabled by browsers on non-HTTPS origins (except `localhost`). Passage must be served over HTTPS in production for passkeys to work.

### 2. Per-IP Rate Limiting Is In-Memory

The sliding-window IP limiters live in the process heap and reset on restart. This is acceptable for single-instance home-lab deployments, but burst attacks can succeed immediately after a process restart. Persistent rate limiting (e.g. Redis-backed) would be required for multi-instance or adversarial deployments.

Per-account password-login throttling is separate and **is** persistent: `login_throttle` is a SQLite table keyed by the lowercased username, so a lockout survives a restart. Locks expire automatically (`auth.lockout_minutes`), and an admin can clear one early from the Users page.

### 3. `SameSite: Lax` Is Not Full CSRF Protection

Modern browsers have inconsistencies in when `SameSite: Lax` cookies are sent. The synchronizer token (HMAC-signed `_csrf` field) is the authoritative CSRF defence; `SameSite: Lax` is an additional layer.

### 4. Password Reset Token in URL

The reset token appears in the path `/reset/{token}` and may be logged by the chi access logger. In a home-lab context this is an acceptable trade-off. Production deployments should review access log retention and access controls. Reset tokens are single-use with a 1-hour expiry.

### 5. RSA Key Size Is 2048 Bits

The OIDC signing key is RSA-2048. While still considered acceptable, 3072-bit RSA or an elliptic-curve key (P-256 or P-384) would provide a stronger security margin. Rotating to an EC key would require a migration-triggered key regeneration.

### 6. WebAuthn Challenges Are Single-Instance

WebAuthn challenges are persisted in SQLite (as of Phase 6 of the security audit). If two Passage instances were run against the same database simultaneously, there would be a race on challenge consumption. Passage is designed for single-instance deployments; this is not a supported configuration.

---

## Section 4 — Security Event Webhook

Passage can POST every recorded authentication event (login success/failure, logout, passkey and magic-link use, registration) to an operator-supplied HTTP endpoint — useful for alerting, for example turning a burst of failed logins into a notification. It is disabled unless `security.webhook_url` (env `PASSAGE_SECURITY_WEBHOOK_URL`) is set.

### Payload

Each delivery is a `POST` with `Content-Type: application/json` and exactly these fields — nothing else:

| Field | Example | Notes |
|---|---|---|
| `event` | `login.failure` | One of the event names shown in the admin security log |
| `outcome` | `failure` | `success`, `failure`, or `throttled` |
| `username` | `alice` | As submitted, truncated to 128 bytes |
| `user_id` | `01f1b0a5…` | Empty when no user matched (e.g. unknown username) |
| `ip` | `192.0.2.10` | Client address without the port |
| `user_agent` | `Mozilla/5.0 …` | Truncated to 256 bytes |
| `detail` | `invalid password` | Free-form context, truncated to 512 bytes |
| `created_at` | `2026-11-10T12:34:56Z` | RFC 3339, UTC |

**Deliberately not sent:** passwords and password hashes, session IDs or cookie values, CSRF tokens, OAuth authorization codes or tokens, password-reset and magic-link tokens, and the internal event ID. A receiver learns that an event happened; it never receives a credential that could be replayed.

### Signature

When `security.webhook_secret` is set, the raw request body is signed with HMAC-SHA256 under that secret and the digest is sent as:

```
X-Passage-Signature: sha256=<hex>
```

Verify against the **exact raw body bytes** before parsing them, then compare in constant time:

```go
mac := hmac.New(sha256.New, []byte(secret))
mac.Write(rawBody)
want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
if !hmac.Equal([]byte(want), []byte(r.Header.Get("X-Passage-Signature"))) {
    http.Error(w, "bad signature", http.StatusUnauthorized)
    return
}
```

### Delivery guarantees

- **Asynchronous.** `Recorder.Record` writes to SQLite as before and only enqueues the event on a buffered channel (256 slots). A slow, hanging, or dead endpoint can never delay or fail a login.
- **At-most-once.** One attempt per event with a per-request timeout (`security.webhook_timeout_seconds`, default 5 s, range 1–60). There is no retry queue and no persistence: if the endpoint is down, times out, answers non-2xx, or the queue overflows, the event is dropped with a WARN log. The authentication event log in the admin UI remains the durable record.
- **In-memory only.** Events still queued when Passage shuts down are discarded.
- **Never fatal.** Delivery errors are logged server-side only; they are never surfaced to the authenticating user and cannot change an auth outcome.

Set `webhook_secret` whenever the receiver is not on the same trusted host: the signature is what lets the receiver tell a genuine Passage delivery from one forged by anything that can reach the endpoint.

### Example: ntfy

ntfy does not accept this payload as-is, so point `webhook_url` at a small relay (a few lines of shell/Python) that receives the JSON and republishes it through ntfy's JSON publish API (`POST https://ntfy.sh` with `{"topic":"...","message":"..."}`) — no ntfy-specific code ships with Passage.

---

## Section 5 — Operational Security Checklist

| Item | Requirement |
|---|---|
| Database file permissions | `chmod 600 passage.db` — readable only by the Passage process user |
| Secure cookies | `PASSAGE_SESSION_COOKIE_SECURE=true` must be set in production |
| Network binding | Passage should only listen on `127.0.0.1` or a private interface — never `0.0.0.0` exposed to the internet |
| Reverse proxy configuration | The reverse proxy must strip any inbound `X-Passage-*` headers before forwarding requests to upstream services, and must only forward requests to Passage's `/auth/*` endpoint — not to the admin UI |
| Admin credentials | The initial admin account should use a strong passphrase. Add a passkey (WebAuthn credential) as a second factor. |
| CSRF key | `PASSAGE_CSRF_KEY` should be set to a long random value in production (e.g. `openssl rand -hex 32`). If left unset, Passage will still start but the anonymous CSRF protection falls back to cookie-only signing, which provides weaker defence against subdomain attacks. |
| Security webhook | If `PASSAGE_SECURITY_WEBHOOK_URL` is set, also set `PASSAGE_SECURITY_WEBHOOK_SECRET` and verify `X-Passage-Signature` at the receiver; otherwise anything that can reach the endpoint can forge events. |
| HTTPS | TLS must be terminated at the reverse proxy. WebAuthn will not work without HTTPS. |
| Log retention | Access logs contain request paths, including `/reset/{token}` paths. Implement appropriate log retention and access controls. |
| `govulncheck` | Run `govulncheck ./...` periodically and after Go toolchain updates. |
