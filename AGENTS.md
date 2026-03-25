# AGENTS.md — Passage

This file is read by AI coding agents at the start of every session. Read it fully before writing a single line of code.

---

## What is Passage?

Passage is a self-hosted authentication proxy for home labs. It implements the **forward-auth pattern**: a reverse proxy (Nginx, Traefik, Caddy) sends every request to Passage's `/auth/*` endpoint before forwarding it to the upstream service. Passage returns `200 OK` if the request is authenticated, or redirects to the login page if not.

**Key characteristics:**
- Single static Go binary — no CGo, no external runtime dependencies
- SQLite backing store via `modernc.org/sqlite` (pure Go driver)
- Web UI built with `html/template` + `embed.FS` + Bulma 1.0.2 CSS framework
- Supports username/password (bcrypt), passkeys (WebAuthn), and OAuth 2.0 / OIDC provider

---

## Module and Go Version

```
Module: github.com/crueber/passage
Go:     1.22+
CGO:    DISABLED — CGO_ENABLED=0 must always work
```

---

## Project Structure

```
passage/
  cmd/passage/          # main.go (thin entry point), run.go (wires everything)
  internal/
    config/             # config loading — env vars + optional YAML
    db/                 # SQLite open + goose migrations
      migrations/       # *.sql embedded migration files (001_*.sql, 002_*.sql, …)
    user/               # model, store, service, handler
    app/                # model, store, service (host pattern matching)
    session/            # model, store, service, middleware
    forwardauth/        # /auth/nginx, /auth/traefik, /auth/start, /auth/sign_out
    admin/              # admin UI handlers + middleware
    email/              # go-mail wrapper + embedded templates
    oauth/              # OAuth 2.0 / OIDC provider — authorize, token, userinfo, JWKS
    webauthn/           # WebAuthn registration and authentication ceremonies
    web/
      templates/        # html/template files, embedded via embed.FS
      static/           # bulma.min.css, passage.css, htmx.min.js, passkey.js
  docs/                 # nginx/traefik config examples
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
| bcrypt cost | Minimum 10, default 12 |
| Reset tokens | Single-use, 1-hour expiry, 32 bytes of `crypto/rand` entropy |

---

## Database Conventions

- All migrations live in `internal/db/migrations/` as numbered SQL files: `001_initial.sql`, `002_add_sessions.sql`, etc.
- Migrations are embedded via `//go:embed migrations/*.sql` and run via goose at startup.
- Always enable on every connection:
  ```sql
  PRAGMA journal_mode=WAL;
  PRAGMA foreign_keys=ON;
  ```
- Primary keys are UUIDs stored as `TEXT` (not integers).
- Every table has `created_at` and `updated_at` columns.

---

## UI Conventions

- Use `html/template` with `{{define}}` partials for shared layout pieces; each admin page template is a standalone `{{define}}` that calls shared partials (`admin-header`, `admin-nav`, `admin-flash`, `admin-footer`).
- **Bulma 1.0.2** is the CSS framework — use Bulma utility classes and components. Avoid inventing new class names for things Bulma already covers.
- `passage.css` owns all theme customisation: CSS custom property overrides (brand colours, sidebar width, footer colours, `--passage-max-width`), the fixed-width container, responsive breakpoints, sidebar min-height, and footer styles. Do not put theme-specific CSS elsewhere.
- **Admin layout structure** (required on every admin page):
  ```html
  <div class="passage-admin-body">
    <div class="passage-admin-container">
      <div class="passage-admin-shell">
        {{template "admin-nav" .}}
        <main class="passage-admin-content"> … </main>
      </div>
      {{template "admin-footer" .}}
    </div>
  </div>
  ```
  - `passage-admin-body`: flex column, fills viewport below navbar, pushes footer to bottom.
  - `passage-admin-container`: centres content at `--passage-max-width` (1280px) with responsive side padding.
  - `passage-admin-shell`: flex row (sidebar + content), `align-items: stretch` so the sidebar background fills the full shell height.
  - `passage-admin-footer`: full-bleed footer bar with MIT license, GitHub link, and copyright.
- htmx is used for progressive enhancement in the admin UI only. **Core flows must work without JavaScript.**
- Every `<input>` must have a paired `<label for="...">` — never use placeholder as a label.
- Every page must have a unique, descriptive `<title>`.
- Accessibility: WCAG AA contrast, `:focus-visible` rings, semantic HTML, `aria-` attributes where needed.
- Dark mode is automatic via `@media (prefers-color-scheme: dark)` — all colour tokens have dark-mode overrides in `passage.css`. Do not hardcode colours in templates.

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
