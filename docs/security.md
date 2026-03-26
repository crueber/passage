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

### 2. Rate Limiting Is In-Memory

The rate limiter state lives in the process heap and resets on restart. This is acceptable for single-instance home-lab deployments, but burst attacks can succeed immediately after a process restart. Persistent rate limiting (e.g. Redis-backed) would be required for multi-instance or adversarial deployments.

### 3. `SameSite: Lax` Is Not Full CSRF Protection

Modern browsers have inconsistencies in when `SameSite: Lax` cookies are sent. The synchronizer token (HMAC-signed `_csrf` field) is the authoritative CSRF defence; `SameSite: Lax` is an additional layer.

### 4. Password Reset Token in URL

The reset token appears in the path `/reset/{token}` and may be logged by the chi access logger. In a home-lab context this is an acceptable trade-off. Production deployments should review access log retention and access controls. Reset tokens are single-use with a 1-hour expiry.

### 5. RSA Key Size Is 2048 Bits

The OIDC signing key is RSA-2048. While still considered acceptable, 3072-bit RSA or an elliptic-curve key (P-256 or P-384) would provide a stronger security margin. Rotating to an EC key would require a migration-triggered key regeneration.

### 6. WebAuthn Challenges Are Single-Instance

WebAuthn challenges are persisted in SQLite (as of Phase 6 of the security audit). If two Passage instances were run against the same database simultaneously, there would be a race on challenge consumption. Passage is designed for single-instance deployments; this is not a supported configuration.

---

## Section 4 — Operational Security Checklist

| Item | Requirement |
|---|---|
| Database file permissions | `chmod 600 passage.db` — readable only by the Passage process user |
| Secure cookies | `PASSAGE_SESSION_COOKIE_SECURE=true` must be set in production |
| Network binding | Passage should only listen on `127.0.0.1` or a private interface — never `0.0.0.0` exposed to the internet |
| Reverse proxy configuration | The reverse proxy must strip any inbound `X-Passage-*` headers before forwarding requests to upstream services, and must only forward requests to Passage's `/auth/*` endpoint — not to the admin UI |
| Admin credentials | The initial admin account should use a strong passphrase. Add a passkey (WebAuthn credential) as a second factor. |
| CSRF key | `PASSAGE_CSRF_KEY` should be set to a long random value in production (e.g. `openssl rand -hex 32`). If left unset, Passage will still start but the anonymous CSRF protection falls back to cookie-only signing, which provides weaker defence against subdomain attacks. |
| HTTPS | TLS must be terminated at the reverse proxy. WebAuthn will not work without HTTPS. |
| Log retention | Access logs contain request paths, including `/reset/{token}` paths. Implement appropriate log retention and access controls. |
| `govulncheck` | Run `govulncheck ./...` periodically and after Go toolchain updates. |
