# AGENTS.md — Passage

This file is read by AI coding agents at the start of every session. Read it fully before writing a single line of code.

---

## What is Passage?

Passage is a self-hosted authentication proxy for home labs. It implements the **forward-auth pattern**: a reverse proxy (Nginx, Traefik, Caddy) sends every request to Passage's `/auth/*` endpoint before forwarding it to the upstream service. Passage returns `200 OK` if the request is authenticated, or redirects to the login page if not.

**Key characteristics:**
- Single static Go binary — no CGo, no external runtime dependencies
- SQLite backing store via `modernc.org/sqlite` (pure Go driver)
- Web UI built with `html/template` + `embed.FS` + Tailwind CSS v4 (compiled locally, vendored output)
- Supports username/password (bcrypt), passkeys (WebAuthn), and OAuth 2.0 / OIDC provider

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
  cmd/passage/          # main.go (thin entry point), run.go (wires everything — all DI happens here)
  internal/
    config/             # config loading — YAML file + PASSAGE_* env var overrides
    db/                 # SQLite open + goose migrations
      migrations/       # *.sql embedded migration files (001_*.sql … 010_*.sql)
    user/               # model, store, service, handler, magic links, setup tokens
    app/                # model, store, service (host pattern matching, per-app session duration, auth method flags)
    session/            # model, store, service, middleware (RequireSession)
    forwardauth/        # /auth/nginx, /auth/traefik, /auth/start, /auth/sign_out
    admin/              # admin UI handlers, RequireAdmin middleware, settings store, audit log
    email/              # go-mail wrapper + embedded templates
    oauth/              # OAuth 2.0 / OIDC provider — authorize, token, userinfo, JWKS, PKCE
    webauthn/           # WebAuthn registration/authentication ceremonies + SQLite credential/challenge stores
    csrf/               # CSRF middleware: ProtectAnonymous (double-submit) + ProtectAuthenticated (session-bound HMAC)
    ratelimit/          # in-memory sliding-window limiter + chi Middleware
    web/
      templates/        # html/template files, embedded via embed.FS (user pages at top level, admin pages in admin/)
      static/           # passage.css (generated: compiled+minified Tailwind output), htmx.min.js, passkey.js
      ui/               # input.css — Tailwind v4 source (@theme tokens + @layer components); rebuild with `make css`
    testutil/           # NewTestDB(t) — in-memory SQLite with migrations, for tests
  docs/                 # nginx/traefik config examples, security.md, forward-auth.md
  tools/                # tailwindcss standalone CLI binary (gitignored — fetch the v4.x release to rebuild CSS)
  Makefile              # css / build / vet / test targets
  Dockerfile            # multi-stage build; runtime mounts /data volume for SQLite
  docker-compose.yml    # local deployment example
  passage.example.yaml  # copy to passage.yaml — full config reference
  .env.example          # PASSAGE_* env var reference
```

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
| `gopkg.in/yaml.v3` | YAML config file parsing |

---

## Runtime Architecture

All wiring lives in `cmd/passage/run.go` — construction order matters. Key facts:

- **Top-level context**: `signal.NotifyContext` (SIGINT/SIGTERM). Every background goroutine and the HTTP server shutdown hang off this context. Never start a goroutine without wiring it to a cancellable context.
- **Background cleanup goroutines** (started in `run()`): expired sessions (hourly), WebAuthn challenges (10 min), OAuth codes/tokens (hourly), rate-limiter cleanup (5 min).
- **Construction order**: settings store and app store are built *before* `session.NewService` because the session service reads the global `session_duration_hours` setting and per-app duration overrides (via the unexported `appDurationAdapter` at the wiring layer). Cross-package adapters live in `run.go`, not in the packages themselves.
- **Dashboard handler**: `/` (the "My Apps" page) is served by `user.Handler.GetDashboard` — not a run.go closure — so it can be regression-tested (see `internal/user/handler_test.go`). `user.NewHandler` takes an `AppLister` (satisfied by `*app.Service`) and a `userContextReader` (wired to `session.UserFromContext`) at the consumer boundary, because `internal/session` imports `internal/user`.
- **First-run bootstrap**: if no admin user exists, `user.SetupTokenManager` generates a one-time token logged to stdout, valid 1 hour. `/setup` self-disables (`IsActive()` checked per request) once any admin exists.
- **OAuth signing key**: one RSA key stored in SQLite (`oauthStore.GetOrCreateRSAKey`), served via `/.well-known/jwks.json`.
- **Single template set**: `web.Parse` parses `templates/*.html` and `templates/admin/*.html` into one `*template.Template` — user and admin pages share one `{{define}}` namespace. The `csrfField` template function must be provided in the `FuncMap`.

## Routing & Middleware (chi)

Route groups in `run.go`; when adding routes, pick the right group:

| Group | Middleware | Routes |
|---|---|---|
| Global | `RequestID`, `RealIP`, `Logger`, `Recoverer`, `web.SecurityHeaders()` | everything |
| Public JSON | none | `/healthz`, passkey auth routes, `/.well-known/*`, `/oauth/*` |
| Anonymous forms | `csrf.ProtectAnonymous` | `/login`, `/register`, `/reset`, `/login/magic`, `/setup` |
| Session-required | `session.RequireSession` + `csrf.ProtectAuthenticated` | `/`, passkey profile routes |
| Admin | `admin.RequireAdmin` + `csrf.ProtectAuthenticated` | `/admin/*` |

- Rate limiting: `ratelimit.Middleware(limiter)` applied per-route (`/login`, `/reset`, `/oauth/token`, `/setup`). Limiters are in-memory sliding-window, configured in the `ratelimit` config section. Read-only OAuth endpoints (discovery, JWKS, userinfo) are deliberately NOT rate-limited.
- Logout is a GET that only revokes the session cookie — no CSRF token by design.
- Passkey endpoints are JSON APIs driven by `passkey.js` — no CSRF token needed (WebAuthn does not submit cross-origin credentials).

## Configuration

- `config.Load(path)` reads YAML (default `passage.yaml`, override with `-config`), then applies `PASSAGE_*` env var overrides. A missing config file is **not** an error — defaults + env are enough.
- Every config change must be validated in `Config.Validate()` (uses `errors.Join` — collect all errors, don't fail on the first).
- `server.base_url` is required for anything that builds absolute URLs (email links, WebAuthn RP ID/origins, OIDC discovery). WebAuthn falls back to `localhost` / `http://localhost:8080` when unset (dev only).
- See `passage.example.yaml` and `.env.example` for the full reference. Update them when adding config keys.

## Deployment & CI

- **CI** (`.github/workflows/ci.yml`): on every push/PR runs `go mod verify`, `go vet ./...`, `go test -race ./...`, and a **CSS drift check** — rebuilds `internal/web/static/passage.css` from `input.css` with the pinned tailwindcss CLI (sha256-verified) and fails if the committed output differs, so `input.css` edits always ship with a fresh `make css` run. On push to `main` or `v*` tags builds a multi-arch (amd64/arm64) image and publishes to `ghcr.io/crueber/passage` with version injected via build args.

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

- All migrations live in `internal/db/migrations/` as numbered SQL files: `001_initial.sql` … `010_magic_link_tokens.sql`. New migrations are the next number; never edit an applied migration.
- SQLite is opened via `db.Open(ctx, path, logger)` which runs migrations and sets `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`. Do not open the driver directly.
- `db.Open` calls `SetMaxOpenConns(1)` — a single writer connection avoids `SQLITE_BUSY` under concurrent load. Don't raise it casually.
- goose runs via the **non-global Provider API** (`goose.NewProvider`), safe for concurrent test use. Never use goose global functions.
- A ping failure with SQLite error code 14 (`SQLITE_CANTOPEN`) is rewritten to a human-readable "check directory/permissions" error — preserve this when touching `db.go`.

---

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
  - `admin-header`: JS-free drawer toggle (`#admin-nav-toggle` checkbox, `.sr-only`), top bar with wordmark breadcrumb, "My Apps" and "Sign out".
  - `admin-nav`: sidebar with section labels (Overview/Manage/System), inline-SVG icons via `{{template "ic-*"}}` (defined in `templates/icons.html`), `.is-active` + `aria-current="page"` for the current section.
  - `admin-footer`: closes the shell and renders the full-width footer (license, GitHub, copyright).
- htmx is used for progressive enhancement in the admin UI only. **Core flows must work without JavaScript.**
- Dark mode is automatic via `@media (prefers-color-scheme: dark)` — one semantic token-override block in `input.css` redefines colours and every component flips with it. Do not hardcode colours in templates.
- Every page must have a unique, descriptive `<title>`.
- Accessibility: WCAG AA contrast, `:focus-visible` rings, semantic HTML, `aria-` attributes where needed.

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

## Quick Session Checklist

Before writing any code:
- [ ] Read this file fully
- [ ] Read all files related to the task (never guess at existing code)
- [ ] Confirm `CGO_ENABLED=0` will still work after your changes
- [ ] Run build verification commands after completing work
