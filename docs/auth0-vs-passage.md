# Auth0 vs Passage — reconciled feature inventory

Audit date: 2026-11-10
Passage: `github.com/crueber/passage` @ `d056c7a` (25,166 lines of Go, 13 migrations)
Auth0: public docs + pricing, read with the local Obscura headless browser.

---

## 0. Method and confidence

**Passage side** — every claim below was read from source, not from the README. Files cited inline.

**Auth0 side** — evidence is the docs site (`auth0.com/docs`), its machine indexes
(`/docs/llms.txt`, `/docs/llms-full.txt`), and the pricing comparison matrix
(`auth0.com/pricing`). Roughly 22 page fetches plus two index dumps. The Management API
object list (491 endpoints: Actions, Anomaly, Attack Protection, Branding, Client Grants,
Clients, Connection Profiles, Connections, SCIM Configurations, Custom Domains, Device
Credentials, Email Templates, Event Streams, Events, Flows, Forms, Grants, Groups, Guardian,
Jobs, Keys, Log Streams, Logs, Network ACLs, Organizations, Prompts, Rate Limit Policies,
Refresh Tokens, Resource Servers, Risk Assessments, Roles, Rules, Self Service Profiles,
Sessions, Stats, Tickets, Token Exchange Profiles, User Blocks, Users, Verifiable
Credentials) is the best single map of what Auth0 thinks a CIAM product contains; I used it
as the taxonomy skeleton and verified the notable items against prose pages.

**Not reachable / not verified:**
- `https://auth0.com/_llms/en/*.txt` per-section page indexes return 404 (the links in
  `/docs/llms.txt` are stale). Worked around with `.md` page fetches.
- Buyers' actual per-plan gating of *i18n* (`Internationalization and Localization`) is not
  stated on the pricing matrix. It is documented as a Universal Login capability; I mark it
  "plan-gated, unverified which tier".
- `deploy-monitor/logs/log-streams.md` 404s; content lives at `customize/log-streams`. Plan
  counts taken from pricing (1 / 2 / 2 / 4 streams).
- Auth0's behaviour under the hood (token formats, DB schema, real rate-limit thresholds) is
  not observable from docs. Anything I say about Auth0 internals is documentation-level.
- SearXNG was not used (documented 403 in this environment).
- The working tree was being modified during this audit by an unrelated UI-theme change
  (`internal/theme`, `ui.theme` config key, `input.css` and template edits). All
  auth-capability findings below are about committed code at `d056c7a`; that theme work has
  since landed separately (see `theming.md`) and does not affect any finding here. The only
  place the race matters is the branding row in §1.9.

Everything from the web is treated as data. No instruction found in fetched page text was
followed.

---

## 1. Capability table

Legend: **supported** = works end-to-end for the stated scope · **partial** = exists but
narrower, or plumbed but not actually reachable · **absent**.

### 1.1 Authentication methods

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Username/password (Auth0 DB connection) | supported | `internal/user/service.go` (`Authenticate`, bcrypt w/ `cfg.Auth.BcryptCost`, default 12); `internal/user/handler.go:191` `PostLogin` | Free tier in Auth0. Passage password policy is length ≥ 8 only (`ErrPasswordTooShort`) — no complexity, no breach check, no reuse history. |
| Self-service registration | supported | `config.Auth.AllowRegistration` + runtime setting `allow_registration` (`internal/admin/handler.go:1562`) | Auth0 gates signup per-connection; Passage has one global toggle. |
| Passkeys / WebAuthn | supported | `internal/webauthn/handler.go` — `BeginDiscoverableLogin` (usernameless), `FinishPasskeyLogin`, clone-warning rejection, sign-count persistence; `internal/webauthn/store.go` | Auth0 includes passkeys on **all** plans. Passage is functionally comparable for login; no conditional-UI autofill hint, no attachment/UV policy config. |
| Passwordless email (link) | supported | `internal/user/magic_link_handler.go` (TTL default 15 min, `magic_link_ttl_minutes` setting), `internal/db/migrations/010_magic_link_tokens.sql` | Auth0 has both link **and** OTP. Passage link only. |
| Passwordless SMS / voice | absent | — | Requires a paid SMS provider; deliberately out of scope for a home lab. |
| Social connections (Google, GitHub, …) | absent | — | No outbound IdP support anywhere in `internal/`. Auth0: unlimited social on all plans. |
| Enterprise connections (SAML, OIDC, AD/LDAP, ADFS, Ping, Azure AD, Google Workspace) | absent | — | Auth0: 1 connection free, then plan tiers/B2B. |
| Custom database connections (script-backed user store) | absent | — | Professional+ in Auth0. |
| MFA factors (push, SMS, voice, OTP, WebAuthn, email, Duo, recovery codes) | absent | — | Passage passkeys are a *login method*, not a second factor: no step-up, no "password then passkey". Auth0: Pro MFA factors at Essentials ($35), enterprise factors at Professional ($240), Adaptive MFA is an add-on. |
| Step-up / `acr_values` / `max_age` / `prompt=login` | absent | `internal/oauth/handler.go:135` `Authorize` reads only `response_type, client_id, redirect_uri, scope, state, nonce, code_challenge*` | No re-auth forcing. |
| Adaptive / risk-based MFA | absent | — | Add-on in Auth0. |
| Email verification | absent (and inaccurately reported) | `internal/oauth/service.go:427` hardcodes `email_verified: true`; same in `UserInfo` | Reasonable for admin-created accounts, wrong once self-registration is on: a user can register with someone else's address, then use password reset on it. |

### 1.2 Session management

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Server-side sessions | supported | `internal/session/service.go` — 32-byte `crypto/rand` hex token, DB row, `ExpiresAt` | Cleaner revocation story than Auth0 cookie sessions. |
| Absolute lifetime | supported | `sessionDurationHours()` resolution: per-app → DB setting `session_duration_hours` → `cfg.Session.DurationHours` (default 24 h) | |
| Idle/rolling timeout | absent | `ValidateSession` only checks `ExpiresAt` | Sessions are absolute-expiry only. |
| Per-app lifetime override | partial (dead code) | `app.SessionDurationHours` exists (`internal/app/model.go`, migration `008`), resolved in `session/service.go`; **but every caller passes `appID = nil`** — `internal/user/handler.go:217,306,615`, `internal/user/magic_link_handler.go:150`, `internal/webauthn/handler.go:471` | The admin UI lets you set a per-app duration and it has no effect. Advertised-but-inert; fix before adding anything else. |
| Admin session revocation (single / all-for-user) | supported | `internal/admin/handler.go:1504` `PostRevokeSession`, `:598` `PostRevokeAllUserSessions`; public-ID indirection so the bearer token never lands in URLs (`migrations/011`) | Auth0 equivalent is the Management API Sessions endpoints. |
| User-side session list / "sign out everywhere" | absent | — | Users cannot see or kill their own sessions. |
| Refresh tokens | supported | `internal/oauth/service.go:261` — 30-day TTL, opaque, DB-stored | |
| Refresh token rotation | supported | `MarkRefreshTokenUsed` before issuing the new pair; double-spend → `ErrRefreshUsed` (`service.go:321`) | |
| Refresh token **reuse detection** (revoke family) | absent | Old token is burned, but a stolen *newer* token keeps working; no family/lineage table | Auth0 does this automatically. Cheap to add given the existing rotation. |
| Session/refresh revocation on password change | supported | `user.Service` calls `SessionRevoker.RevokeAllByUser`; `oauth` re-checks `IsActive` + app access at refresh (`service.go:333-347`) | Good, and stronger than many self-hosted IdPs. |
| Back-channel logout (OIDC) | absent | — | Auth0: Enterprise only. |
| RP-initiated logout / `end_session_endpoint` | absent | `/logout` (`internal/user/handler.go:439`) revokes the session and clears the cookie, but there is no OIDC logout endpoint, no `id_token_hint`, no `post_logout_redirect_uri` | Real interop gap: Grafana/Nextcloud/Outline expect an end-session endpoint. Discovery document doesn't advertise one (`handler.go:75`). |
| Cookie hardening | supported (above Auth0 defaults) | `__Host-` prefix when `CookieSecure` (`config.SessionConfig.EffectiveCookieName`), `HttpOnly`, `SameSite=Lax` | Nice touch. |

### 1.3 Authorization

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Per-app access grants | supported | `user_app_access` table; `app.Service.HasAccess`; enforced in forward-auth (`forwardauth/handler.go:checkAuth`) **and** at OAuth authorize *and* re-checked at refresh | Stronger than Auth0 "connection enabled for app": access is per user↔app. |
| RBAC roles | supported (app-scoped) | `internal/app/groups_roles.go`, `migrations/012_app_groups_roles.sql` (`app_roles`), `assignments.go` | Auth0 RBAC: not on Free, Essentials+. |
| Groups + role→group inheritance | supported | `app_role_groups`, `user_app_groups`, `EffectiveGroupNames` (direct + inherited), resolved at token issuance | Equivalent to Auth0 roles+groups composition; Auth0 adds **permissions** (role→permission), Passage has none. |
| Roles/groups in tokens | supported | `buildIDToken` emits `roles` and `groups` arrays + `is_admin` (`service.go:427`); `UserInfo` mirrors them | Apps can do local authorization off the id_token. |
| Permissions / scopes registry per API | absent | `Authorize` accepts any `scope` string and echoes it verbatim into the code and token (`service.go:96`, `handler.go:135`) — no registration, no validation, no consent | Auth0 has resource servers + scopes + consent. |
| Consent screen | absent | Authorize immediately issues a code for any client the user has access to | Defensible for first-party homelab apps. |
| Organizations / multi-tenancy (B2B) | absent | — | Passage's app-scoped groups are a *per-app* namespace, not a *per-customer* tenant. Auth0: 5 orgs free, 10 Essentials/Pro, custom at Enterprise. |
| Fine-grained authorization (FGA) | absent | — | Product in its own right; skip. |
| Machine-to-machine (`client_credentials`) | absent | `Token` switch: only `authorization_code`, `refresh_token` (`handler.go:239`) | No service accounts. Relevant if Passage should gate cron jobs/APIs. |

### 1.4 OAuth 2.0 / OIDC protocol surface

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Authorization code flow | supported | `internal/oauth/handler.go` `Authorize`/`Token` | |
| PKCE | supported (S256 only) | `internal/oauth/service.go:133-155` rejects `plain` and unknown methods, validates challenge length 43 | Deliberate, matches OAuth 2.1. |
| OIDC discovery | supported | `/docs`-equivalent at `handler.go:75` — issuer, authorize, token, userinfo, jwks, `S256`, RS256 | Missing `end_session_endpoint`, `revocation_endpoint`, `introspection_endpoint`, `device_authorization_endpoint`. |
| JWKS + `kid` (RFC 7638 thumbprint) | supported | `handler.go:98`, `oauth/store.go:GetOrCreateRSAKey` (persisted in `oidc_config`) | One RSA-2048 key, no rotation endpoint. |
| ID token (RS256) | supported | `service.go:427` — `iss/sub/aud/exp/iat/auth_time/nonce/name/email/preferred_username/email_verified/is_admin/roles/groups` | `auth_time` correctly omitted on refresh. |
| Access tokens | partial (opaque, DB-backed) | `oauth_tokens` table, 1 h TTL, `expires_in: 3600` hardcoded | Not JWTs, no `aud`, no resource indicators. Only `/oauth/userinfo` can consume them. |
| Token revocation (RFC 7009) | absent | no route | |
| Token introspection (RFC 7662) | absent | no route | Opaque tokens make this the natural way for resource servers to validate. |
| Device authorization flow (RFC 8628) | absent | — | Homelab-relevant (CLI tools, TV apps). |
| Token exchange | absent | — | Professional+ in Auth0. |
| PAR (RFC 9126) | absent | — | |
| JAR (signed request objects) | absent | — | |
| RAR (`authorization_details`) | absent | — | |
| DPoP / mTLS / `private_key_jwt` | absent | — | `private_key_jwt` is Enterprise-only at Auth0; DPoP documented as a supported hardening option. |
| FAPI security profile | absent | — | Auth0 add-on. |
| CIBA (backchannel auth) | absent | — | Add-on. |
| Implicit / hybrid / ROPG | absent | — | Correctly omitted (deprecated/insecure). |

### 1.5 User management

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| CRUD users | supported | `internal/admin/handler.go:336-617`; `internal/user/store.go` | |
| Account activation/deactivation | supported | `User.IsActive`, checked in session validation *and* token validation | |
| Admin password reset for a user | supported | `PostResetUserPassword` | |
| User self-service password reset | supported | `handler.go:332` — single-use 1 h token, uniform response + 200 ms floor to defeat timing enumeration | Better anti-enumeration than most OSS IdPs. |
| Profile fields | partial | `User{Username, Email, Name, IsAdmin, IsActive}`; display name is self-service on `/profile` (linked from the top-bar name), username and email are admin-edited; a vestigial `Roles string` column always `"[]"` | No arbitrary `user_metadata`/`app_metadata`. Auth0 metadata is core. |
| User search / filter / pagination | absent | `admin.GetUsers` calls `userStore.List` and renders everything | Fine at 20 users, painful at 200. |
| Bulk import / export | absent | no CSV/JSON endpoints; no Jobs equivalent | Auth0: user import on all plans, Jobs API. |
| Invitations | supported | admin page `/admin/users/invite` sends a single-use link; `invitations` table (`migrations/029`) stores no user until the recipient accepts and chooses credentials | Works while public registration is off. |
| Email verification | absent | see 1.1 | |
| Account linking | absent | — | |
| SCIM / JIT provisioning | absent | — | Auth0: inbound SCIM free/B2B, Enterprise tier. |
| Audit log of admin actions | supported | `internal/admin/audit.go` — 22 action constants, filterable page `GetAuditLog` (`migrations/003`) | Good; but see 1.7 — it records no authentication events. |

### 1.6 Extensibility

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Actions (Node.js, 7 triggers, versioning, modules, npm) | absent | — | Free 5 / Essentials 10 / Pro 15 / Ent 30+. |
| Rules & Hooks | absent | — | EOL at Auth0. |
| Forms (visual flows) | absent | — | |
| Event streams / webhooks | absent | — | Homelab-idiomatic replacement would be a plain webhook or ntfy, not an event bus. |
| Marketplace / integrations | absent | — | |
| Custom claims hook | partial | Fixed claim set + `roles`/`groups`; no per-app claim mapping | |

### 1.7 Security / attack protection

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Rate limiting | supported (per IP only) | `internal/ratelimit/ratelimit.go` — in-memory sliding window, per-IP, per-route config (`rate_limit` block: login, reset, oauth token, setup, register, magic link) | Auth0 brute-force is **per account**; suspicious-IP is per IP. Passage has only the latter, and it resets on restart (documented in `docs/security.md`). |
| Brute-force protection (per account) | absent | no per-username counter or lockout | Biggest single security gap relative to Auth0's free tier. |
| Breached-password detection | absent | — | Auth0 Pro+ (and Credential Guard add-on). Requires a feed or local list. |
| Bot detection / CAPTCHA | absent | — | Add-on. |
| Suspicious IP throttling | partial | per-IP limiter covers the velocity case for login paths | No cross-account scoring, no block list. |
| Anomaly detection / Security Center | absent | — | Enterprise. |
| CSRF | supported (well done) | `internal/csrf/csrf.go` — `ProtectAnonymous` double-submit with server-side key + `ProtectAuthenticated` session-bound HMAC, 4 h TTL, `_csrf` field or `HX-CSRF-Token` | Stronger than many products; ephemeral key generated in `run.go` if unset. |
| Security headers / CSP | supported (strict) | `internal/web/middleware.go` — `script-src 'self'; style-src 'self'`, `frame-ancestors 'none'` | |
| Open-redirect protection | supported | `forwardauth/handler.go:AuthStart` and login `rd` handling both reject `//`, `/\` | |
| Token storage | supported | session tokens and OAuth tokens are random opaque values; client secrets bcrypt-hashed (`apps.client_secret_hash`); reset/magic-link tokens 32 bytes `crypto/rand` | |
| Signing key rotation | absent | single RSA key, no `kid` rotation flow | |
| Multi-instance safety | absent by design | in-memory limiter, WebAuthn challenge race documented in `docs/security.md` §3.6 | |
| Encryption of secrets at rest in config/env | absent | SMTP password and CSRF key are plain env/YAML | Normal for this class. |

### 1.8 Audit + logging

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Tenant log of every auth event (type codes, per-event detail) | absent | only `middleware.Logger` request logs; no auth event table | This is the largest operational gap. Auth0 logs are the primary debugging tool and the input to log streaming. |
| Log retention by plan (1 / 5 / 10 / 30 days) | n/a | SQLite, operator-controlled | |
| Log streaming (Datadog, Splunk, S3, Azure, HTTP, SSE) | absent | — | Free: 1 stream; Essentials/Pro: 2; Enterprise: 4 + prioritized security streams. |
| Event streams (async, per-event type) | absent | — | 1 / 3 / 4 / 8 by plan. |

### 1.9 Branding, domains, i18n

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Hosted login page | supported | `internal/web/templates/*.html` | Auth0 "Universal Login". |
| Brand customization | partial | Tailwind theme tokens in `internal/web/ui/input.css`; no admin-editable branding (an uncommitted `ui.theme` / `internal/theme` feature was mid-flight during this audit) | Auth0: brand customization on all plans; "Customize Signup & Login" Essentials+. A colour-theme selector is the right-sized version of this; a page builder is not. |
| Per-app / per-org branding | absent | one global look | Explicit non-goal in `README.md` ("not meant to have … brandable screens"). |
| Custom domains | partial | the whole product runs on one operator-chosen host; `server.base_url` drives WebAuthn RP ID, OIDC issuer, email links | Auth0: 1 custom domain on Free/Essentials/Pro; 20+ on Enterprise. Passage needs exactly one, so functionally satisfied. |
| Email templates | partial | two hardcoded templates, embedded (`internal/email/templates/*.html/.txt`) | Auth0: email workflow Essentials+; template customization + i18n. |
| Internationalization | absent | English-only templates | Auth0 documented; tier gating unverified. |
| ACUL / JS page-level customization | absent | — | Deliberate. |

### 1.10 Developer experience / operations

| Auth0 capability | Passage | Evidence | Notes |
|---|---|---|---|
| Management API (491 endpoints) | absent | HTML admin UI only; no JSON admin API | |
| Authentication API (db connections, passwordless, MFA tickets, etc.) | absent | — | |
| SDKs (202 pages of them) | absent | — | Passage is plain OIDC; any OIDC client library works. |
| Deploy CLI | absent | — | |
| Terraform provider | absent | — | |
| Local dev story | supported (different model) | `CGO_ENABLED=0 go build`, single binary + SQLite, `docker-compose.yml`, embedded assets | Auth0: cloud tenants + separate dev/prod envs (Essentials+). Passage's "environment" is a file. |
| Deployment automation | partial | Dockerfile + compose + GH Actions multi-arch publish; no Helm chart | |
| Tenants / environments | absent by design | one tenant per database | Auth0: 1 free, 3 Essentials, unlimited Enterprise. |
| Observability | partial | structured `slog` JSON, `/healthz` with version | No `/metrics`, no traces. |
| Migrations / upgrade safety | supported | goose provider, embedded numbered SQL, applied at open (`internal/db/db.go`) | No downgrade path — standard for goose. |
| SSO across apps | supported (inherent) | one cookie on the Passage host; every app redirects there | Auth0 "Cross App SSO" is Professional+; Passage gets it for free by architecture. |
| MFA for admin UI | absent | admin is password/passkey like everything else | Auth0 has dashboard MFA. |

---

## 2. What Passage already has that is genuinely equivalent

For its niche — *one login for a rack of self-hosted apps, behind a reverse proxy* — Passage
covers more of Auth0's **core** than its feature count suggests, because Auth0's own core is
narrower than its marketing: authorization code + PKCE + refresh rotation + discovery + JWKS +
userinfo is the whole of what a normal web app consumes.

**Effectively equivalent:**
- **OIDC provider for web apps.** Code flow, S256-only PKCE, rotating refresh tokens, RS256
  id_token with correct `auth_time`/`nonce` handling, discovery, JWKS with a stable `kid`,
  userinfo. Grafana, Gitea, Nextcloud, Outline, Grist do not care that Auth0 has 400 more
  endpoints. Two places Passage is *stricter* than a default Auth0 tenant: `plain` PKCE is
  refused, and app access is re-checked at refresh time so a revoked user cannot ride a
  30-day refresh token.
- **Passkeys.** Discoverable (usernameless) login, clone-warning rejection, sign-count
  tracking, per-device naming, self-service add/remove. Auth0 includes passkeys at $0 too —
  so this is parity, not an advantage, but it is *real* parity.
- **RBAC-ish authorization.** App-scoped roles, groups, and role→group inheritance resolved
  into `roles`/`groups` claims is the 80% of Auth0 RBAC that consumer web apps use. Auth0
  charges $35/mo before RBAC is available at all.
- **Per-user, per-app access control.** Stronger than Auth0's connection-level gating.
- **Session revocation.** Instant, server-side, per session or all-for-user, on password
  change, and surfaced in an admin table. Auth0 needs Management API calls for the same.
- **Password reset + magic links** with 32-byte single-use tokens, 1 h expiry, TTL-configurable
  magic links, and anti-enumeration timing padding.
- **CSRF and CSP.** Session-bound HMAC tokens plus a genuinely strict CSP; both better than
  what most self-hosted IdPs ship.

**Where Passage exceeds Auth0 for this niche — i.e. Auth0 has no equivalent:**
1. **Forward-auth.** `/auth/nginx` + `/auth/traefik`, host-pattern app resolution
   (`path.Match` globs), per-user app access, and `X-Passage-Username/Email/Name/User-ID/Is-Admin`
   identity headers. Auth0 is an OIDC/SAML authority, not a proxy gatekeeper; the Auth0-shaped
   answer is "run oauth2-proxy next to it", i.e. two more moving parts.
2. **Zero-cost, zero-tenant operations.** One binary, one SQLite file, `chmod 600`, done. No
   MAU meter, no tenant sprawl, no dev/prod separation upsell.
3. **Deployment footprint.** `CGO_ENABLED=0`, embedded templates/CSS/JS, no external cache,
   no Redis, no Postgres, no sidecar.

**Where the gap actually is (and it is not "features", it is operations + identity breadth):**
- No authentication event log → you cannot answer "who logged in from where, and did it fail?"
- No per-account lockout → credential stuffing against one account is only bounded by IP.
- No OIDC logout or revocation/introspection → apps cannot cleanly sign a user out or validate
  an opaque token.
- No MFA → a single phishable password still opens everything.
- No upstream IdP federation → no "sign in with the Google account I already have", and no
  bridging to an existing Authentik/Keycloak.
- No user-visible session control → a lost phone cannot be handled by the user.
- Advertised-but-inert per-app session duration.

That is the honest reconciliation: Passage matches Auth0 on the *protocol and login-method*
core, exceeds it on *proxy integration and operational simplicity*, and is behind on
*observability, anti-abuse, and identity federation* — none of which require Auth0's
architecture to close.

---

## 3. Ranked feature list

Sizes: **S** ≈ ≤1 day, **M** ≈ 2–3 days, **L** ≈ 1–2 weeks (including tests, migrations,
template + CSS rebuild, docs). Every item assumes the repo's non-negotiables: pure Go, no CGo,
SQLite, no global state, `go test -race`, `make css` after template changes.

### Tier 1 — high value, fits the mission, small/medium

| # | Feature | Why it fits a self-hosted forward-auth proxy | Size | Depends on | Verdict |
|---|---|---|---|---|---|
| 1 | **Authentication event log** — record `login.success`, `login.failure`, `login.throttled`, `passkey.login`, `magiclink.login`, `logout`, `oauth.authorize`, `oauth.token`, `session.revoke` into `audit_log` with user, IP, UA, app, method; filterable admin page reusing the existing audit UI | The single most useful thing Auth0 has that Passage lacks. Home labs are debugged with "did my login even arrive?" Cost is one table + a few call sites because the audit store, filter and page already exist | S | `internal/admin/audit.go`, `migrations/003` | **Essential** |
| 2 | **Per-account login throttling + temporary lockout** — counter keyed by username (not just IP), exponential backoff, "unlock" button in the admin user page, failure count shown in the event log | Auth0's free brute-force protection is per account; Passage's per-IP window is defeated by IPv6 rotation and CGNAT. Also makes the event log actionable | S/M | item 1 (for visibility); `internal/ratelimit` | **Essential** |
| 3 | **OIDC RP-initiated logout** — `end_session_endpoint` in discovery, `id_token_hint`, `post_logout_redirect_uri` validated against the app's registered URIs, revoke session + refresh tokens | Every mainstream self-hosted app tries to call it; today they get a 404 and leave stale sessions. This is *the* clearest interop bug against Auth0's free tier | S/M | `internal/oauth/handler.go`, app model (needs a registered post-logout URI list) | **Essential** |
| 4 | **`/oauth/revoke` (RFC 7009) + `/oauth/introspect` (RFC 7662)** — authenticated by client credentials only | Access tokens are opaque, so introspection is the only way a resource server can validate them; revocation is how apps clean up on unlink. Low effort, closes two spec holes | S | `internal/oauth/store.go` | **Essential** |
| 5 | **Refresh-token reuse detection** — add a `family_id`/`parent_id` to `oauth_refresh_tokens`; on reuse of a burned token, revoke the whole family and emit an auth event | Auth0 does this automatically and it is the main defence once a token leaks. Passage already rotates, so this is one migration plus one query | S | item 1 | **Valuable** |
| 6 | **Fix per-app session duration, then add idle timeout** — thread the resolved `appID` into `CreateSession` at every call site, and add an optional `last_seen_at` rolling idle window | The admin UI already exposes the setting and it silently does nothing; adjunct apps (e.g. an admin panel) genuinely want a shorter window than a media server | S | `internal/session`, 5 call sites listed in §1.2 | **Essential (bug)** |
| 7 | **MFA: TOTP second factor** — enrol/verify TOTP (pure Go), recovery codes, per-user "require MFA", admin policy "require MFA for admins"; passkeys become usable as a *second* factor too | Closes the biggest real-world weakness (one phishable password = whole rack). Auth0's MFA is a $35/mo feature; TOTP is ~400 lines with no vendor | M | session/login flow; `internal/webauthn` ceremony reuse for step-up | **Essential** |
| 8 | **User self-service sessions** — "Devices & sessions" page in the user dashboard: list sessions (IP, UA, created, expires, current marker), revoke one, "sign out everywhere" | Lost phone / shared laptop is the homelab threat model. Reuses `ListByUser`, `RevokeSession`, `RevokeAllByUser` | S | none new | **Valuable** |
| 9 | **Stop lying about `email_verified`** — send a verification link on self-registration, store `email_verified_at`, emit the real value in id_token/userinfo; gate magic-link login for unverified self-registered accounts | Today a self-registered user can claim someone else's address and then receive that person's password reset. Small, but it is a correctness bug | S | `internal/email` (new template), migration | **Valuable** |
| 10 | **Per-app claim mapping** — optional JSON/inline list in app settings for extra static claims and for renaming/omitting `groups`; validate the claim set at save time | Cheap customization that replaces 90% of "I need an Action to add a claim" requests, without an execution engine | S/M | `buildIDToken`, admin app form | **Valuable** |
| 11 | **Generic forward-auth route + Caddy docs** — add `/auth/generic` (same logic as traefik), document Caddy `forward_auth`, HAProxy and Traefik label snippets | Caddy is the default proxy for a large share of home labs; the code already keys off `X-Forwarded-Host`, so this is documentation plus one route | S | `internal/forwardauth`, `docs/` | **Valuable** |
| 12 | **Security-event notifications** — optional webhook or ntfy URL for "new device login", "account locked", "admin settings changed", "refresh reuse detected" | The homelab-correct answer to Auth0's log streaming: push to the thing the operator already watches, no aggregator required | M | item 1 | **Valuable** |

### Tier 2 — valuable, larger

| # | Feature | Why it fits | Size | Depends on | Verdict |
|---|---|---|---|---|---|
| 13 | **Upstream identity providers (OIDC/OAuth login connections + account linking)** — "Continue with Google/GitHub", or federate to an existing Authentik/Keycloak; map external subject → local user | The one Auth0 capability most home labs actually miss: reusing an identity they already have instead of creating another password. Turns Passage from an IdP into a broker without giving up being one. Widest blast radius on this list (connection model, linking table, login UI, tests) | L | new `internal/connection` package; `user` model needs identities; existing login flow changes | **Valuable** |
| 14 | **Step-up authentication** — `prompt=login`/`max_age`/`acr_values` handling plus a per-app "require re-auth for this app" toggle | Lets the admin panel and a password manager demand a fresh login while Jellyfin stays relaxed. Small subset of Auth0's continuous session protection, at homelab scale | M | item 7 (MFA) if `acr_values` means "mfa" | **Valuable** |
| 15 | **Access policies per app** — require group/role, CIDR allowlist, time-of-day window, admin-only | Replaces the most common Auth0 Actions recipe ("block this app outside the LAN") with config instead of a JS engine. Very homelab: kids' accounts, camera UIs, admin tools | M | `app` model + admin form; `forwardauth.checkAuth` and OAuth authorize | **Valuable** |
| 16 | **JWT access tokens + audience/resource indicators + a real scope registry** | Required the moment anyone protects an API (not just a UI) with Passage; also fixes "any scope string is accepted and echoed". Prerequisite for `client_credentials` and for introspection to be optional | L | `internal/oauth`; signing key reuse; scope model in `app` | **Valuable** |
| 17 | **Admin REST API + API tokens** — `/api/v1/{users,apps,sessions,audit}`, token auth, same handlers behind a thin adapter | Automation (Ansible, a GitOps repo, exporting users before a migration) is the concrete homelab need. Deliberately *not* Auth0's 491 endpoints: read/write for the 4 resources Passage has | L | stable JSON shapes; CSRF exemption path for token auth | **Valuable** |
| 18 | **Device authorization flow (RFC 8628)** — `/oauth/device_authorization`, user code entry page, polling | CLIs and TV apps cannot show a login form; this is the standard answer and it is ~200 lines on top of the existing code store | M | `internal/oauth` | **Valuable** |
| 19 | **Consent screen (opt-in per app)** — "this app is asking for: openid, profile, email, groups" with approve/deny persisted per user↔app | Only matters once third-party/less-trusted clients are registered; cheap insurance for item 13 | M | scope registry (item 16) for anything beyond the fixed scope set | **Valuable (low)** |
| 20 | **`/metrics` for Prometheus** — auth counters, session gauges, limiter hits, token issuance | The observability half of item 1 for people who already run Grafana/Prometheus (which they do, because Passage protects it) | S/M | none | **Valuable (low)** |
| 21 | **LDAP/AD bind as an authentication source** — `go-ldap` (pure Go) verifying credentials against a directory, JIT user creation | Only worth it if the operator runs Samba AD/OpenLDAP; otherwise it duplicates item 13 for no benefit | L | item 13's identity model | **Valuable (niche)** |
| 22 | **Signing key rotation** — `kid` history in JWKS, "rotate signing key" admin action, old key retained until tokens expire | Enables recovery from a leaked DB; pairs with the existing OAuth secret rotation UX | M | `oauth_store`, JWKS | **Valuable (low)** |

### Tier 3 — skip: enterprise CIAM features that contradict Passage's design

| Feature | Why skip |
|---|---|
| **Actions / Rules / Hooks / Forms** (Node.js execution, triggers, versioning, npm) | Requires an embedded JS runtime, a sandbox, a versioning store and a debugging UI. Passage's answer is a fixed Go hook or a webhook; a policy engine is how this product becomes unmaintainable. |
| **Organizations, self-service SSO, home-realm discovery, org invitations, org M2M** | Multi-tenant B2B. A home lab has one tenant and a handful of users; per-app groups already give the only namespace anyone needs. |
| **SCIM provisioning / directory sync** | Needs a schema-mapping UI and a spec-complete endpoint set to be worth anything; the actual job (create 6 users) is faster in the admin UI. |
| **Fine-grained authorization (FGA), RAR, PAR, JAR, DPoP, mTLS, `private_key_jwt`, FAPI profile** | Compliance-grade sender-constraining and request hardening. Real cost, zero homelab payoff; PKCE S256 already covers the threat that matters (code interception). |
| **CIBA, Token Vault, MCP/AI-agent identity, verifiable credentials** | Product surface for machine identities and delegated third-party API access. Irrelevant to "log into Jellyfin". |
| **Bot detection / CAPTCHA, breached-password cloud feeds, anomaly detection, Security Center, adaptive/risk MFA** | All vendor-data or ML products. A homelab alternative is a static password blocklist and item 2, not a risk score. |
| **Log streaming to Datadog/Splunk/S3/Azure + event streams** | Aggregator plumbing for fleets. Item 12 (webhook/ntfy) is the right-sized version. |
| **Multiple tenants / environments, tenant ACLs, per-tenant custom domains, ACUL JS page customization, per-org branding, i18n framework** | Directly contradicts the stated non-goals in `README.md` ("not meant to have dozens of auth scopes, brandable screens, or complex policy engines"). One look, one tenant, one host. |
| **SMS/voice passwordless (Twilio and friends)** | Paid third-party dependency, per-message cost, and SMS is the weakest factor available. Magic links and passkeys cover the need better. |
| **Management API at Auth0 scale, Deploy CLI, Terraform provider, 200 SDKs** | Item 17 (a small admin API) captures the automation value; the rest is integration surface for an ecosystem Passage does not have. |
| **Implicit, hybrid, ROPG, custom database connections (script-backed)** | Deprecated or architecturally backwards. Auth0 keeps them for migration customers. |

---

## 4. What Passage should explicitly NOT copy (and why)

1. **Per-MAU metering and plan-gated security.** Auth0 charges $35/mo before RBAC and standard
   MFA, and puts back-channel logout, `private_key_jwt` and continuous session protection behind
   Enterprise. Passage's value proposition is that every security feature is in the binary.
   Shipping "Passage Pro" would delete the reason the project exists.
2. **A JavaScript extension runtime.** Actions exist because Auth0 cannot know your business
   logic and cannot ship code for you. Passage can: the answer is a Go hook point plus a
   webhook, not a sandboxed interpreter with npm access.
3. **A hosted, branding-first login page.** Universal Login's customization surface (ACUL,
   page templates, per-org branding, i18n) exists to make a *vendor's* login page look like
   *your* product. Passage is your product.
4. **Multi-tenancy.** Tenants, Organizations and per-org connections are the CIAM answer to
   "my customer is a company". The homelab answer is "there is one of me".
5. **Vendor risk scoring.** Bot detection, breached-password feeds, adaptive MFA, Security
   Center and anomaly detection are all "we have a data lake you don't". They cannot be
   self-hosted honestly, and pretending otherwise (a bundled CAPTCHA, a stale breach list)
   is worse than not shipping them.
6. **Standards theatre.** DPoP, mTLS, PAR, JAR, RAR and FAPI certification are meaningful for
   regulated financial clients and are pure complexity here; PKCE S256 plus short-lived
   rotating refresh tokens is the correct security/effort point.
7. **The 491-endpoint Management API, Deploy CLI and a Terraform provider.** This is the
   integration economy of a SaaS. A deliberately small, documented JSON admin API (item 17)
   gives the same automation benefit for a product with four resources.
8. **Log shipping to aggregators.** Do not build a stream framework; POST an event to a URL
   the operator configures.
9. **Account linking / identity merging as a general feature.** Only worth building as part of
   item 13, and only the one-directional case (external subject → existing local user).

---

## 5. Defects found while reading (independent of Auth0)

These are cheap and worth fixing regardless of the feature roadmap:

1. **Per-app session duration is inert.** `app.SessionDurationHours` is stored, editable, and
   resolved by `session.Service.sessionDurationHours`, but every `CreateSession` caller passes
   `nil` for `appID`, so the app branch never runs. (`internal/user/handler.go:217,306,615`,
   `internal/user/magic_link_handler.go:150`, `internal/webauthn/handler.go:471`.)
2. **`scope` is unvalidated and echoed.** `Authorize` stores whatever the client sends and
   `Token` returns it in `scope`. Either validate against a fixed set or stop returning it.
3. **`email_verified` is hardcoded `true`** in both id_token and userinfo, including for
   self-registered accounts.
4. **`users.roles` column is dead** — always written as `"[]"`, never read
   (`internal/user/model.go:37`, `service.go:73,107,253`). Drop it in a migration.
5. **No OIDC logout/revocation endpoints**, so third-party clients cannot clean up; discovery
   documents no `end_session_endpoint` and no `revocation_endpoint`.
6. **Access tokens are opaque with no introspection**, which means a resource server has no
   way to validate a token except by calling `/oauth/userinfo` on every request.

---

## 6. Sources

Passage: `AGENTS.md`, `README.md`, `docs/security.md`, `docs/forward-auth.md`,
`cmd/passage/run.go`, `internal/{config,db,user,session,app,admin,oauth,webauthn,email,csrf,ratelimit,web,forwardauth}`
(incl. all 13 migrations).

Auth0: `auth0.com/pricing` (plan matrix), `auth0.com/docs/llms.txt`, `auth0.com/docs/llms-full.txt`,
and the documentation pages for: docs home, Authenticate, Manage Users, Extend, Secure,
Monitor/Deploy, Login, Passwordless, Enterprise Connections, Identity Providers, MFA overview,
MFA factors, Attack Protection, Continuous Session Protection, Sessions & Cookies, RBAC,
Organizations, Actions overview, Custom Domains, Refresh Token Rotation, Logs.
