# AGENTS.md — Passage

This file is read by AI coding agents at the start of every session. Read it fully before writing a single line of code.

---

## What is Passage?

Passage is a self-hosted authentication proxy for home labs. It implements the **forward-auth pattern**: a reverse proxy (Nginx, Traefik, Caddy) sends every request to Passage's `/auth/*` endpoint before forwarding it to the upstream service. Passage returns `200 OK` if the request is authenticated, or redirects to the login page if not. It is also an **OAuth 2.0 / OIDC provider**, which is the better fit for applications that speak OIDC natively.

**Key characteristics:**
- Single static Go binary — no CGo, no external runtime dependencies
- SQLite backing store via `modernc.org/sqlite` (pure Go driver)
- Web UI built with `html/template` + `embed.FS` + Tailwind CSS v4 (compiled locally, vendored output)
- Sign-in by password (bcrypt), passkey (WebAuthn), magic link, upstream OIDC provider, or password plus TOTP with recovery codes; administrators can also invite accounts by email
- Per-app access grants, roles, groups and an optional access policy (group/role/CIDR/hours/admin-only), a read-only admin API with bearer tokens, Prometheus metrics and an authentication event log
- Everything past bootstrap is configured in the admin UI and stored in SQLite: the config file only sets the listener, public URL, database path, key material, cookie shape and logging

---

## Module and Go Version

```
Module:    github.com/crueber/passage
Go:        1.25 (go.mod requires 1.25.0; toolchain 1.26.1)
CGO:       DISABLED — CGO_ENABLED=0 must always work
Version:   injected at build time via -ldflags "-X main.version=..." (defaults to "dev")
```

---

## Project Structure

```
passage/
  cmd/passage/          # main.go (thin entry point), run.go (wires everything — all DI happens here), metrics.go
  internal/
    config/             # config loading — YAML file + PASSAGE_* env var overrides
    db/                 # SQLite open + goose migrations
      migrations/       # *.sql embedded migration files (001_*.sql … 034_*.sql)
    user/               # model, store, service, handler, magic links, invitations, profile, setup tokens
    app/                # model, store, service (host pattern matching, per-app session duration, auth method flags)
    session/            # model, store, service, middleware (RequireSession), user sessions page
    forwardauth/        # /auth/nginx, /auth/traefik, /auth/start, /auth/sign_out
    admin/              # admin UI handlers, RequireAdmin middleware, settings store, audit log, pagination
    settings/           # database-backed feature settings: keys, defaults, typed accessors, ApplyToConfig
    authlog/            # authentication event store + recorder (security log, webhook, retention)
    email/              # go-mail wrapper + embedded templates
    oauth/              # OAuth 2.0 / OIDC provider — authorize, token, userinfo, JWKS, keyring, PKCE
    webauthn/           # WebAuthn registration/authentication ceremonies + SQLite credential/challenge stores
    mfa/                # TOTP (RFC 6238) + single-use recovery codes, pending login challenges, AES-256-GCM secret encryption (cipher.go/key.go)
    idp/                # upstream OIDC providers: discovery, PKCE, id_token verification, account links
    policy/             # per-app access policy evaluation (group/role/CIDR/admin-only/hours) — pure
    adminapi/           # read-only /api/v1 + API tokens (SHA-256 at rest)
    metrics/            # Prometheus registry, text encoder, HTTP instrumentation (no deps)
    csrf/               # CSRF middleware: ProtectAnonymous (double-submit) + ProtectAuthenticated (session-bound HMAC)
    ratelimit/          # in-memory sliding-window limiter + chi Middleware, and the SQLite-backed
                        # per-account (login_throttle) and per-address (magic_link_throttle) throttles
    theme/              # colour-theme registry (All / Names / Lookup / Canonical / Default)
    web/
      templates/        # html/template files, embedded via embed.FS (user pages at top level, admin pages in admin/)
      static/           # passage.css + themes.css (both generated), app.js, htmx.min.js, passkey.js
      ui/               # input.css (Tailwind v4 source; rebuild with `make css`) + themes/<name>.css (plain CSS)
    testutil/           # NewTestDB(t) — in-memory SQLite with migrations, for tests
  .forgejo/workflows/   # CI (test, image, release) and publish-github.yml — the development repository's CI
  scripts/              # publish-to-github.sh + publish/*.yml (the GitHub workflows installed at publish time)
  docs/                 # config examples plus security, forward-auth, theming, idp, app-access-policies,
                        # admin-api, metrics, jwt-access-tokens, oauth-signing-key-rotation, auth0-vs-passage;
                        # plans/ holds tracked design notes and docs/demo.webm|webp the README demo
  screenshots/          # README gallery (generated from a demo instance, not hand-edited)
  site/                 # static marketing page published to GitHub Pages: index.html, one hand-written
                        # style.css carrying the app's tokens, img/ (cropped webp screenshots); no build step
  tools/                # build-css.sh, build-themes.sh, fetch-tailwind.sh (tracked) + the gitignored
                        # tailwindcss standalone CLI binary
  Makefile              # css / themes / assets / build / vet / test targets
  Dockerfile            # multi-stage build; runtime mounts /data volume for SQLite
  docker-compose.yml    # local deployment example
  passage.example.yaml  # copy to passage.yaml — full config reference
  .env.example          # PASSAGE_* env var reference
```

There is no `.github/` in the development tree: it is installed from `scripts/publish/` when a release is published.

---

## Dependencies

All dependencies are **pure Go — no CGo**. Do not introduce any dependency that requires CGo.

| Package | Purpose |
|---|---|
| `github.com/go-chi/chi/v5` | HTTP router |
| `github.com/pressly/goose/v3` | DB migrations |
| `github.com/wneessen/go-mail` | SMTP email |
| `golang.org/x/crypto` | bcrypt password hashing |
| `modernc.org/sqlite` | Pure Go SQLite driver (no CGo) |
| `github.com/go-webauthn/webauthn` | WebAuthn/passkeys |
| `github.com/golang-jwt/jwt/v5` | JWT signing and verification (OAuth id_token) |
| `github.com/skip2/go-qrcode` | TOTP enrollment QR codes (pure Go, no transitive dependencies) |
| `gopkg.in/yaml.v3` | YAML config file parsing |

---

## Runtime Architecture

All wiring lives in `cmd/passage/run.go` — construction order matters. Key facts:

- **Top-level context**: `signal.NotifyContext` (SIGINT/SIGTERM). Every background goroutine and the HTTP server shutdown hang off this context. Never start a goroutine without wiring it to a cancellable context.
- **Background cleanup goroutines** (started in `run()`): expired sessions and idle sessions (hourly), WebAuthn and MFA challenges (10 min), OAuth codes/tokens (hourly), authentication-log retention (daily), expired invitations (hourly), magic-link throttle rows (hourly), in-memory rate-limiter windows (5 min).
- **Construction order**: settings store and app store are built *before* `session.NewService` because the session service reads the global `session_duration_hours` setting and per-app duration overrides (via the unexported `appDurationAdapter` at the wiring layer). Cross-package adapters live in `run.go`, not in the packages themselves.
- **Dashboard handler**: `/` (the "My Apps" page) is served by `user.Handler.GetDashboard` — not a run.go closure — so it can be regression-tested (see `internal/user/handler_test.go`). Pins live on `user_app_access.favorite`, so they are per-user and vanish with the access grant; `GetDashboard` puts pinned apps first with a stable sort and `POST /apps/{id}/favorite` toggles one (no access row = no-op). The page renders both views: **Comfortable** grouped rows and an **Iconized** shelf/tile launcher. `data-app-view` resolves from the `passage_app_view` browser cookie → `users.app_view` → Comfortable; `?view=` is the no-JS switch fallback and sets the cookie. `app.js` updates the attribute/cookie instantly, migrates the old `passage.density` localStorage value, and runs the Ctrl/⌘K command launcher (type-ahead over server-rendered links, arrow/Enter/Esc, focus trap); mobile uses a floating search button. Tile stars are always visible. `user.NewHandler` takes an `AppLister` (satisfied by `*app.Service`) and a `userContextReader` (wired to `session.UserFromContext`) at the consumer boundary, because `internal/session` imports `internal/user`.
- **Feature settings live in the database, not the config file.** `passage.yaml` (and the matching `PASSAGE_*` env vars) is bootstrap-only: listen address, `server.base_url`, database path, session-cookie shape, `security.encryption_key`, `csrf.key`, logging. Everything else is stored in the `settings` table and edited in **Settings** (`internal/admin/settings_form.go`). `internal/settings` owns the keys, defaults, typed accessors (`String`/`Raw`/`Bool`/`Int`, all of which fall back rather than fail a request) and `ApplyToConfig`, which copies the startup values into the config snapshot as fallbacks. **No setting requires a restart.** Registration, MFA policy, session lifetime, sign-in copy, theme, metrics and idle timeout are read per use; bcrypt cost and SMTP are read per hash/email; the webhook resolves its URL, secret and timeout per delivery; rate limits and lockout thresholds are re-applied through `Handler.SetSettingsReloader` after a successful save (changing a limit clears that limiter's in-memory windows). Adding a setting means: a key + default in `internal/settings`, a field in `settings_form.go`, a migration row seeding the default (`INSERT OR IGNORE`), and a live read (or a reload hook for stateful components).
- **First-run bootstrap**: if no admin user exists, `user.SetupTokenManager` generates a one-time token logged to stdout, valid 1 hour. `/setup` self-disables (`IsActive()` checked per request) once any admin exists.
- **OAuth signing keys**: a keyring in `oauth_signing_keys` (`internal/oauth/keyring.go`). The newest non-retired key signs; every non-retired key is served in `/.well-known/jwks.json`; verification selects by `kid`, so older id_tokens keep working after a rotation. Started from the legacy single key in `oidc_config` on first boot. Admin rotate/retire/delete, never the last active key.
- **Magic links sign in existing accounts only, silently**: every request renders the same "if there is an account at that address, it has been sent" page, so an unknown address, a blocked client and a mail failure are indistinguishable (no enumeration oracle). Requests for addresses with no user are recorded in `magic_link_throttle` (keyed by client address); the threshold and window are the admin Magic link rate limit (`rate_limit_magic_link_requests` per `rate_limit_magic_link_window_minutes`, re-applied on save), and reaching it blocks the address for 24 hours, checked before the lookup. Successful requests are never counted, and the block is persistent so a restart does not lift it. The 24-hour block is fixed in `run.go` (`magicLinkLockout`), not a setting.
- **Step-up auth**: `prompt=login|none`, `max_age` and `acr_values=urn:passage:reauth` are handled at `/oauth/authorize`; a session older than 60 s bounces through the normal login flow back to the same authorize URL (the window is the loop guard). `prompt=none` answers `login_required` only to a registered `redirect_uri`.
- **OAuth access tokens**: issued as RS256 JWTs signed by the current keyring (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `scope`, `client_id`); `aud` is the RFC 8707 `resource` when one was granted, else the client id. `apps.scopes` / `apps.resources` are opt-in per-app registries (one value per line, empty = today's behaviour). Opaque tokens issued before this change still validate through the `oauth_tokens` path, so an upgrade never forces a re-login. Revoking a JWT writes its `jti` to `oauth_revoked_jti`; introspection, userinfo and `ValidateAccessToken` consult it, and the hourly cleanup prunes expired rows.
- **Throttling has two layers.** Request bursts are bounded by in-memory sliding-window limiters (`internal/ratelimit`, reset on restart) whose budgets are the Settings → Rate limits values. Credential guessing is bounded by persistent SQLite throttles that survive a restart: `login_throttle` (per username; `auth.max_login_failures` / `auth.lockout_minutes`) and `magic_link_throttle` (per client address; see the magic-link bullet). Both are re-applied from the database after a settings save.
- **Per-app access policies**: `internal/policy` evaluates group/role/CIDR/admin-only/hours; enforced in forward-auth (403), at OAuth authorize (`access_denied`) and again at the token endpoint (code exchange and every refresh, `invalid_grant`), never on the dashboard. An empty policy returns before any DB work. Empty fields mean no restriction.
- **Upstream IdPs**: providers live in `idp_providers` (migration 028) and are managed at `/admin/providers`; client secrets are sealed with the instance cipher, bound to the provider id. The list is read per request, so an added provider works immediately. Sign-in is state+nonce+PKCE, linked by (provider, subject) then verified email, optionally auto-created. Like passkeys and magic links, it never gets an MFA step.
- **Invitations**: the way an administrator creates an account while `allow_registration` is off. `/admin/users/invite` emails a single-use link (`invitations`, migration 029); no `users` row exists until the recipient opens `/invite/{token}`, chooses a username, display name and password, and the service creates the account — verified, because clicking the link proves mailbox control. The accept route is deliberately outside the registration policy; the invitation row is the authorisation. Re-inviting an address replaces the pending link; a consumed link keeps its `accepted_at` row. Expired, never-accepted rows are pruned hourly. A separate `/profile` page (reached by clicking the display name in the top bar) runs `POST /profile`, which updates only `users.name` via `Store.SetName`, so a user can change their display name any time without touching credentials. The Security page (`/passkeys`) is split into **Passkeys**, **Two-factor authentication** (`?tab=mfa`) and **Password** (`?tab=password`, hidden when `auth_password_enabled` is off) tabs; MFA redirects land on the MFA tab. `POST /password` verifies the current password (skipped when the account has none), rotates the hash, revokes every session and immediately issues a replacement for this browser.
- **Single template set**: `web.Parse` parses `templates/*.html` and `templates/admin/*.html` into one `*template.Template` — user and admin pages share one `{{define}}` namespace. The `csrfField` template function must be provided in the `FuncMap`.

## Routing & Middleware (chi)

Route groups in `run.go`; when adding routes, pick the right group:

| Group | Middleware | Routes |
|---|---|---|
| Global | `RequestID`, `web.TrustedRealIP`, `web.RequestLogger`, metrics counter, `Recoverer`, `web.SecurityHeaders()` | everything; `/static/*` is served here (with strong ETag) |
| Public | none | `/healthz`, `/metrics` (404 when disabled), `/.well-known/*`, `/oauth/*`, `/logout`, `/verify-email/{token}`, passkey login routes, `/login/mfa/passkey/*`, `/login/oidc/*` |
| Anonymous forms | `csrf.ProtectAnonymous` | `/login`, `/register`, `/invite/{token}`, `/reset`, `/reset/{token}`, `/login/mfa`, `/login/magic`, `/setup` (POSTs are rate-limited) |
| API | bearer token (`adminapi.RequireToken`) + limiter | `/api/v1/*` — read-only, no session or CSRF |
| Session-required | `session.RequireSession` + `csrf.ProtectAuthenticated` | `/`, `/apps/{id}/favorite`, `/verify-email/resend`, `/sessions` (+ revoke), `/profile`, `/password`, the MFA routes, the Security page and the passkey profile routes — the last five sit outside the MFA gate so a user who must enrol can reach them |
| Behind the "require MFA" gate | `user.RequireMFA` inside the session group | dashboard, favourites, verification resend, sessions |
| Admin | `admin.RequireAdmin` + `csrf.ProtectAuthenticated` + `RequireMFA` | `/admin/*` |

- Rate limiting: `ratelimit.Middleware(limiter)` is applied per route — sign-in (`POST /login`, `/login/mfa`, `/login/mfa/passkey/*`, `POST /password`), registration (`/register`, `/invite/{token}`), password reset, magic link (`POST /login/magic`, `/verify-email/{token}`, `/verify-email/resend`), OAuth token/revoke/introspect, setup, and the API. The limiters are in-memory sliding windows configured in Settings → Rate limits. Read-only OAuth endpoints (discovery, JWKS, userinfo) are deliberately NOT rate-limited.
- Logout is a GET that only revokes the session cookie — no CSRF token by design.
- Passkey endpoints are JSON APIs driven by `passkey.js` — no CSRF token needed (WebAuthn does not submit cross-origin credentials). A passkey can also satisfy a pending second-factor challenge (`/login/mfa/passkey/*`): those calls are authenticated by the SameSite=Lax `passage_mfa` cookie, bound to the challenge token through the WebAuthn `ChallengeStorer` (`"mfa:"` namespace), and finish through `completeMFAChallenge` — the same path a TOTP code takes.

## Configuration

- `config.Load(path)` reads YAML (default `passage.yaml`, override with `-config`), then applies `PASSAGE_*` env var overrides. A missing config file is **not** an error — defaults + env are enough.
- Only bootstrap keys belong in the config file; feature settings go in the settings table and the admin UI (see the settings bullet above). Every bootstrap key must be validated in `Config.Validate()` (uses `errors.Join` — collect all errors, don't fail on the first); settings-page values are validated on save in `internal/admin/settings_form.go`.
- `server.base_url` is required by `Config.Validate()` — it builds absolute URLs (email links, WebAuthn RP ID/origins, OIDC discovery) and prevents Host-header poisoning on password-reset/invite emails.
- `server.trusted_proxies` (env `PASSAGE_SERVER_TRUSTED_PROXIES`) lists proxy CIDRs/IPs whose forwarding headers (`X-Forwarded-For` rightmost-untrusted hop, falling back to `X-Real-IP`/`True-Client-IP`) are honored by `web.TrustedRealIP` before stripping those headers. Defaults to loopback + RFC 1918 + ULA + link-local + CGNAT/Tailscale (`100.64.0.0/10`); set `trusted_proxies: []` or `PASSAGE_SERVER_TRUSTED_PROXIES=none` when exposed directly without a reverse proxy.
- `security.encryption_key` (env `PASSAGE_SECURITY_ENCRYPTION_KEY`) is the optional AES-256-GCM key that encrypts TOTP secrets at rest: 64 hex characters or base64 of 32 bytes. When unset, `mfa.ResolveKey` creates `<database.path>.key` on first use (hex, mode 0600, `O_CREATE|O_EXCL`); a `:memory:` database gets an ephemeral key. Never log it, and never rotate it by overwriting the file — there is no re-keying path, and a lost key makes enrolled secrets unreadable.
- See `passage.example.yaml` and `.env.example` for the full reference. Update them when adding config keys.

## Deployment & CI

- **CI** (`.github/workflows/`): on every push/PR runs `go mod verify`, `go vet ./...`, `go test -race ./...`, and a **CSS drift check** — rebuilds `internal/web/static/passage.css` from `input.css` with the pinned tailwindcss CLI (`tools/fetch-tailwind.sh` downloads it and verifies the sha256) and fails if the committed output differs, so `input.css` edits always ship with a fresh `make css` run. A second drift step runs `./tools/build-themes.sh --check` for `themes.css`. On push to `main` it builds a multi-arch (amd64/arm64) image with buildah and pushes it to the development registry; on a `v*` tag it also cross-compiles `passage-linux-amd64` and `passage-linux-arm64`, writes `SHA256SUMS.txt`, and publishes the release with those assets.
- **Publishing is one-way.** GitHub is a release channel, not a development repository: the push mirror stays disabled and no development commit is ever pushed there directly. The publish workflow in the development repository (`.forgejo/workflows/publish-github.yml`, run manually with a version bump) tags the development repository and dispatches its CI so it builds and releases that version, then exports the tree, installs the GitHub workflows from `scripts/publish/` (including `pages.yml`), and pushes **one squash commit per release** plus the tag to GitHub — whose own workflows build `ghcr.io/crueber/passage`, the GitHub release and the project website from that commit. Edit `scripts/publish/*.yml` for GitHub-side CI changes; the checked-in `.github/workflows/` exists only in the published tree.
- **The website** (`site/`) is published to GitHub Pages by `scripts/publish/pages.yml`, installed as `.github/workflows/pages.yml` at publish time. It is plain HTML, one hand-written `site/style.css` and local webp images — no build step, no CDN, no JavaScript, and every URL is relative because Pages serves it from `/<repo>/`. Dark mode is `prefers-color-scheme`; `site/style.css` copies the tokens from `internal/web/ui/input.css` by hand, so a token change must be mirrored there. Images under `site/img/` are cropped and downscaled from `screenshots/`, plus a verbatim copy of `docs/demo.webm` and a poster frame extracted from it; regenerate them from those sources rather than hand-editing. The demo player is `preload="none"` with that poster, so the page stays light — the video only downloads when someone presses play. One-time setup on GitHub: **Settings → Pages → Source: GitHub Actions**.

---

## Go Conventions

These are non-negotiable. Follow them on every change.

### 1. Pure Go, no CGo
`CGO_ENABLED=0 go build ./...` must always succeed. Never introduce a dependency that requires CGo.

### 2. Errors are values
Always check errors. Always wrap with `%w`. Never ignore an error without a documented reason.

```go
if err != nil {
    return fmt.Errorf("open db: %w", err)
}
```

### 3. Interfaces at the consumer
Define interfaces in the package that uses them, not in the package that implements them. Do not define interfaces "for mocking" in production packages.

### 4. No global state
No global logger, no global DB connection, no global config. Pass all dependencies explicitly via constructors or function parameters.

### 5. `context.Context` first
Always the first parameter, always named `ctx`. Never store a `context.Context` in a struct field.

### 6. `main` is thin
`main()` calls `run()` and handles the error. All logic lives in `run()` or below.

```go
func main() {
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

### 7. Structured logging with `log/slog`
Use `log/slog` only. JSON handler in production, text handler in development. Pass the logger as an explicit dependency — never use a global logger.

### 8. Formatting
Run `goimports` on every save. Formatting is not debatable.

### 9. Race detector
Always run tests with `go test -race ./...`. The race detector is mandatory in CI.

### 10. Module hygiene
Run `go mod tidy` before every commit.

### 11. Table-driven tests
Use `t.Run` subtests. Mark test helpers with `t.Helper()`.

### 12. `crypto/rand` for security
Never use `math/rand` for tokens, session IDs, passwords, or any security-sensitive value. Always use `crypto/rand`.

### 13. Consistent receivers
Use pointer receivers consistently on a type. Never mix value and pointer receivers on the same type.

### 14. No `init()` with side effects
`init()` must not do I/O, start goroutines, or mutate global state. Prefer explicit initialization called from `run()`.

---

## Security Rules (Non-Negotiable)

| Rule | Detail |
|---|---|
| Random values | Always `crypto/rand` — never `math/rand` for tokens, session IDs, reset tokens |
| SQL queries | Always parameterized — no string concatenation in SQL ever |
| HTML escaping | `html/template` auto-escaping is relied upon — never use `template.HTML()` to bypass without explicit justification and comment |
| Session cookies | `HttpOnly: true`, `Secure: configurable`, `SameSite: Lax` |
| Reset tokens | Single-use, 1-hour expiry, 32 bytes of `crypto/rand` entropy |
| CSRF | Two `internal/csrf` middlewares: `ProtectAnonymous` (double-submit cookie, fails closed — missing cookie ⇒ 403) and `ProtectAuthenticated` (HMAC signed with the session token). Tokens submitted via `_csrf` form field or `HX-CSRF-Token` header. Every state-changing form must render `{{csrfField .CSRFToken}}`. |

---

## Database Conventions

- All migrations live in `internal/db/migrations/` as numbered SQL files: `001_initial.sql` … `034_performance_indexes.sql`. New migrations are the next number; never edit an applied migration.
- **Additive only.** `CREATE TABLE IF NOT EXISTS`, `ALTER TABLE … ADD COLUMN` with a `NOT NULL DEFAULT`, `CREATE INDEX IF NOT EXISTS`. No `DROP`, no table rebuilds, no column renames, and a new column must default to "behaves like before" so an upgrade can never take auth down. Include a best-effort `Down` and a test that reopens a *populated* database.
- Migrations must stay **independent of each other's ordering**: `db.Open` runs goose with `WithAllowOutofOrder(true)` because parallel branches merge files out of numeric order, and a database that has already recorded a higher version must still start when a lower one appears. Never make one migration depend on another running first.
- SQLite is opened via `db.Open(ctx, path, logger)` which runs migrations and sets `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`. Do not open the driver directly.
- `db.Open` calls `SetMaxOpenConns(1)` — a single writer connection avoids `SQLITE_BUSY` under concurrent load. Don't raise it casually.
- goose runs via the **non-global Provider API** (`goose.NewProvider`), safe for concurrent test use. Never use goose global functions.
- A ping failure with SQLite error code 14 (`SQLITE_CANTOPEN`) is rewritten to a human-readable "check directory/permissions" error — preserve this when touching `db.go`.

---

## UI & Template Conventions

- **Tailwind CSS v4** is the CSS framework. Source of truth is `internal/web/ui/input.css`: a `@theme` block of design tokens (brand scale, semantic surface/ink/line/muted colours, radii, shadows) plus `@layer components` classes (`.btn`, `.card`, `.input`, `.label`, `.table`, `.badge`, `.note`, `.stat`, `.empty`, `.sidebar-link`, …). Prefer existing component classes and utilities over inventing new ones.
- `internal/web/static/passage.css` is **generated** — minified Tailwind output, committed. Never hand-edit it. Edit `input.css` and rebuild with `make css` (the `tailwindcss` standalone CLI lives at `tools/tailwindcss`, gitignored; fetch the v4.x release binary for linux/macOS to rebuild). **Always rebuild after any change that could introduce a new class candidate — including docs edits.**
- **Tailwind scan scope is pinned** (`@import "tailwindcss" source(none)` + explicit `@source` lines in `input.css`): only `templates/` and the two JS files are scanned. Without this, Tailwind auto-detects every non-ignored repo file — including markdown — and prose words become CSS candidates (an AGENTS.md edit once generated an `.invisible` utility and failed the CI drift check). If you add a file that contains class names, register it with an `@source` line.
- **Flash partial contract**: any template that renders `{{template "flash" .}}` requires a `Flash *Flash` field on its render data struct. Go templates error at *execution* (→ 500) on missing struct fields — this is invisible at compile time and only surfaces at runtime. The dashboard regression (PR #2/#3) is pinned by `TestHandler_GetDashboard_*` tests in `internal/user/handler_test.go`; keep them passing when touching render data.
- **Strict CSP**: the global `web.SecurityHeaders()` middleware sends `script-src 'self'; style-src 'self'` — the browser silently drops inline `<script>` blocks and `on*=` handler attributes. Never add them. Interactive behavior lives in `internal/web/static/app.js` (loaded with `defer`), driven by `data-` attributes: `data-copy="#id"` (copy target text), `data-confirm="message"` (confirm before form submit), plus the `#select-all-btn` wiring. Verify any new interactive element actually runs — a CSP-blocked handler fails silently with no server-side error.
- Template copy and class names are load-bearing: Go tests assert specific strings and hooks (e.g. `"No users have access."`, `passage-stat`, `tag is-info is-light`). Grep the test files before rewording copy or renaming classes.
- Checkbox option lists (roles, groups, assignments) use the `.check-list` grid component (1-col mobile / 2-col ≥sm) with a name line + muted description line per label — don't stack bare `.checkbox` labels in table cells.
- Use `html/template` with `{{define}}` partials for shared layout pieces; each admin page template is a standalone `{{define}}` that calls shared partials (`admin-header`, `admin-nav`, `admin-flash`, `admin-footer`).
- All templates live in one parsed set (`web.Parse`): user pages in `templates/*.html`, admin pages in `templates/admin/*.html`. `{{define}}` names are global across both — prefix admin templates (`admin-*`, `user-dashboard`) to avoid collisions.
- Forms on every POST route carry `{{csrfField .CSRFToken}}` (or `$.CSRFToken` inside range blocks); templates must include the hidden CSRF input on every POST form.
- **Admin layout structure** — three partials bracket every admin page:
  ```html
  {{template "admin-header" .}}   {{/* opens .admin-shell + topbar, opens flex row */}}
  {{template "admin-nav" .}}      {{/* .sidebar (drawer on mobile) + opens content column */}}
  <main …> … </main>
  {{template "admin-footer" .}}   {{/* closes content column + flex row, renders .app-footer, closes shell */}}
  ```
  - `admin-header`: JS-free drawer toggle (`#admin-nav-toggle` checkbox, `.sr-only`), top bar with wordmark breadcrumb, the admin's name linking to `/profile` (so they can set their own theme), and "Sign out".
  - `admin-nav`: sidebar with section labels (Overview/Manage/System), inline-SVG icons via `{{template "ic-*"}}` (defined in `templates/icons.html`), `.is-active` + `aria-current="page"` for the current section.
  - `admin-footer`: closes the shell and renders the full-width footer (license, GitHub, copyright).
- **Every admin list is paginated** with the shared `admin-pagination` partial and `internal/admin/pagination.go`: ten rows by default, 10/25/100 selectable, `page` (or `with_page` / `without_page` on the app access page) and `per_page` query keys. Each list remembers its chosen size per browser in a `passage_pp_<list>` cookie, used when `per_page` is absent. Never render an unbounded user, app, log or session list.
- **App tabs are task-shaped**: Details (slug, name, description, host pattern, default URL, redirect URIs, active), OAuth (credentials plus the OAuth-only session lifetime and scope/resource registries), Access, Groups, Roles, and Policies last (all-optional access policy). Each tab has its own POST route, so saving one tab never rewrites another tab's fields.
- htmx is used for progressive enhancement in the admin UI only. **Core flows must work without JavaScript.**
- Dark mode is automatic via `@media (prefers-color-scheme: dark)` — one semantic token-override block in `input.css` redefines colours and every component flips with it. Do not hardcode colours in templates.
- Every page must have a unique, descriptive `<title>`.
- Accessibility: WCAG AA contrast, `:focus-visible` rings, semantic HTML, `aria-` attributes where needed.

### Theming

- Colour themes are plain CSS custom-property overrides, one file per theme in `internal/web/ui/themes/<name>.css`. They are **not** Tailwind sources — never `@import` them into `input.css`, and never wrap them in `@layer` (unlayered + `:root[data-theme="x"]` is what makes them beat `passage.css`).
- `internal/web/static/themes.css` is **generated** by `tools/build-themes.sh` (`make themes`) — never hand-edit it, and commit it with the source change. CI runs `./tools/build-themes.sh --check`.
- Registry of record is `internal/theme` (`All`, `Names`, `Lookup`, `Canonical`, `Default`). Filename, `data-theme` value, `ui.theme` value, and registry `Name` are the same slug. Labels describe the palette (`Cool Slate`, `Arctic Blue`, `Warm Retro`), not the upstream project; pre-rename slugs live in `legacyNames` and are rewritten by migration 031.
- Token contract: every theme file must define the full token set in **both** its light `:root[data-theme="x"]` block and its dark `@media (prefers-color-scheme: dark)` block. Colour tokens are 6-digit hex; only `--shadow-*` use `rgb(… / α)`. Full list in `docs/theming.md`.
- The contrast test (`internal/theme/theme_test.go`) is the gate: WCAG AA pairs per block (4.5:1 text, 3:1 `faint`). Never lower a threshold to make a palette pass — retune the palette.
- `TestThemeFiles_BrandRamp` pins the two load-bearing ends of the ramp: it must descend `50` → `950` in both blocks, and `brand-950` must be darker than `canvas` because it is the drawer scrim (`bg-brand-950/40`). Do not invert the ramp for dark mode.
- Full-page templates must carry `<html lang="en" data-theme="{{theme .}}">` and `<link rel="stylesheet" href="/static/themes.css">` after `passage.css`. `TestTemplates_ThemeWiring` enforces both. Theme resolution is server-side: signed-in page data embeds `web.Themed` filled from the user, and public pages fall back to the server default (no `localStorage`, no theme script).
- The theme override belongs to the person, not the browser: Profile saves `users.theme` (`Store.SetTheme`), and Settings → General remains the server default. Pages must render correctly with no JavaScript.

---

## Testing Conventions

- Use real in-memory SQLite (`:memory:`) for tests — do not mock the database layer.
- `internal/testutil` provides a `NewTestDB(t *testing.T)` helper.
- Integration tests use `net/http/httptest`.
- Never use `os.Exit` in tests — use `t.Fatal` or `t.FailNow`.
- Always run with the race detector: `go test -race ./...`

---

## Build Verification

All four of these must pass before considering any work complete:

```bash
# 1. Must compile with CGo disabled
CGO_ENABLED=0 go build ./...

# 2. No vet errors
go vet ./...

# 3. All tests pass with race detector
go test -race ./...

# 4. Module hygiene — go.mod and go.sum are clean
go mod tidy && git diff --exit-code go.mod go.sum

# 5. Generated CSS matches its sources (what CI's drift checks enforce)
make css && ./tools/build-themes.sh
git diff --exit-code internal/web/static/passage.css internal/web/static/themes.css
```

---

## What Agents Must NOT Do

- **No CGo** — hard constraint, no exceptions
- **No `init()` with I/O, goroutines, or global state**
- **No global variables** for loggers, DB connections, or config
- **No `math/rand`** for anything security-sensitive
- **No `template.HTML()`** bypass without an explicit comment explaining why it is safe
- **No inline `<script>` blocks or `on*=` handler attributes in templates** — the strict CSP silently blocks them; put behavior in `internal/web/static/app.js` (see UI Conventions)
- **No unapproved dependencies** — do not add packages not in `go.mod` without flagging it first
- **No scope creep** — do not implement features beyond what the current phase requires (YAGNI)
- **No files outside the project structure** without a documented reason

---

## Documentation Assets

- The README demo (`docs/demo.webm` plus the animated `docs/demo.webp` preview) and every image in `screenshots/` are captured from a demo instance, not written by hand. Re-record or re-capture rather than editing the files. `site/img/` holds cropped, downscaled webp copies of the `screenshots/` gallery, a verbatim copy of `docs/demo.webm` and a poster frame extracted from that video; regenerate them from those sources instead of editing them. Never re-encode, crop, shorten or hand-edit the demo video — it is a generated artefact, copy it as it is.
- Demo material is public: use the fictional account, `*.example.com` hostnames, RFC 5737 documentation addresses, and generic app names. Never capture real hostnames, private addresses, personal names, or an inventory that describes the real lab. Redact app lists in screenshots when they name real services.

---

## Quick Session Checklist

Before writing any code:
- [ ] Read this file fully
- [ ] Read all files related to the task (never guess at existing code)
- [ ] Confirm `CGO_ENABLED=0` will still work after your changes
- [ ] Run build verification commands after completing work
