# Passage Authentication Proxy — Implementation Plan

## Overview

**Passage** is a self-hosted authentication proxy for home lab use. It sits alongside a reverse proxy
(Nginx, Traefik, Caddy) and uses the forward-auth pattern to gate access to downstream applications.
Users authenticate once through Passage; subsequent requests to any protected app are validated via
a lightweight sub-request. Passage is a single, dependency-light Go binary with a SQLite backing
store, an embedded web UI for administration, and a plain-HTML/JS user-facing interface.

The architecture is intentionally simple now and deliberately extensible later: the data model
accounts for per-app access control, future role-based permissions, and future OAuth provider
integration — none of which are implemented in the initial rollout.

---

## Current State Analysis

This is a greenfield project. The repository exists but is empty. No prior code, migrations, or
configuration exists.

---

## Desired End State (Full Plan Scope)

After all phases are complete:

- A single `passage` binary can be started with a config file or environment variables.
- Nginx/Traefik/Caddy can be configured to call Passage's forward-auth endpoint to gate any app.
- Users can log in with username + password through a hosted login page.
- Users can self-register (if enabled by admin) and reset their password via email.
- An admin web UI allows managing users, apps, and active sessions.
- Passkeys (WebAuthn) can be registered and used as a primary or secondary credential.
- Sessions are DB-backed, scoped to a configurable duration, and can be revoked by admins.
- The binary is a single static artifact — no CGo, no external runtime dependencies.

### Verification of End State:
```bash
go build -o passage ./cmd/passage     # must produce a single static binary, no CGo
go test -race ./...                   # all tests pass with race detector
./passage --config passage.yaml       # server starts, SQLite DB created/migrated
curl http://localhost:8080/healthz    # {"status":"ok"}
```

---

## What We Are NOT Doing (In This Plan)

- **No OAuth2/OIDC provider or consumer** — no "Login with Google/GitHub". Extensibility hooks
  will be noted in code comments, but no implementation.
- **No role-based access control (RBAC)** — access is binary: on or off per user/app. The data
  model will have a stub `role` concept so it can be added later without a breaking migration.
- **No reverse proxy functionality** — Passage does not proxy traffic. It only validates sessions.
- **No Kubernetes operator, Helm chart, or Docker Compose** — out of scope for now.
- **No LDAP, SAML, SCIM, or RADIUS** — Passage is username/password + passkeys only.
- **No multi-tenancy** — one Passage instance, one user namespace.
- **No distributed/clustered deployment** — SQLite means single-instance only.

---

## Technology Choices

| Concern | Choice | Reason |
|---|---|---|
| Language | Go 1.22+ | Pure Go, no CGo anywhere |
| Database | SQLite via `modernc.org/sqlite` | Pure Go, no CGo, single file |
| Migrations | `github.com/pressly/goose/v3` | Clean embed.FS integration |
| Password hashing | `golang.org/x/crypto/bcrypt` | Standard, simple API |
| Sessions | Custom (crypto/rand + SQLite) | Full control, zero deps |
| HTTP router | `github.com/go-chi/chi/v5` | No external deps, middleware composition |
| HTML templates | `html/template` + `embed.FS` | Stdlib, auto-escaping, single binary |
| CSS framework | Simple.css (classless, 9.4 KB) | Accessible, semantic, no build step |
| Static assets | `embed.FS` | Bundled into binary |
| Email (SMTP) | `github.com/wneessen/go-mail` | Pure Go, near-zero deps, sane TLS defaults |
| WebAuthn | `github.com/go-webauthn/webauthn` | Only viable Go WebAuthn library |
| Config | env vars + optional YAML file | Standard Go config, no extra dep needed |
| Logging | `log/slog` (stdlib, Go 1.21+) | Structured logging, zero deps |

---

## UI Design Specification

Passage's UI should feel like a **calm utility** — trustworthy, legible, and unobtrusive. It is not
a marketing site. Users interact with it briefly on their way to somewhere else; admins use it
occasionally to manage users and apps. Every design decision should serve that purpose.

### CSS: Simple.css (classless)

Use [Simple.css](https://simplecss.org) v2.x as the sole stylesheet baseline. It is:
- **9.4 KB minified** (2.8 KB gzipped) — a single file, embedded via `embed.FS`
- **Fully classless** — semantic HTML (`<form>`, `<table>`, `<nav>`, `<button>`) renders correctly
  without adding class attributes to Go templates
- **Accessibility-first** — uses `:focus-visible` for keyboard navigation rings, explicit WCAG AA
  contrast targets, `aria-current="page"` nav styling, and clean disabled-state rendering
- **Auto dark mode** — responds to `prefers-color-scheme` with no JavaScript

Ship `simple.min.css` as-is from the official release. Then ship a small `passage.css` (< 2 KB)
that overrides Simple.css variables and adds layout rules for the admin sidebar. Both files are
embedded into the binary.

### Color Palette

Override Simple.css's default blue accent with a calm slate-green:

```css
/* internal/web/static/passage.css */
:root {
  --accent:        #2e6b4f;   /* deep forest green — institutional, trustworthy */
  --accent-hover:  #245840;   /* slightly darker on hover */
  --accent-bg:     #f3f7f5;   /* near-white with a faint green tint */
  --text:          #1a1f1c;   /* near-black with slight green warmth */
  --text-light:    #5a6b62;   /* muted text for secondary labels */
  --bg:            #ffffff;
  --border:        #c8d5cd;   /* cool grey-green border */
  --code-bg:       #eef3f0;
}
```

This palette reads as calm and professional — closer to a terminal or a utility dashboard than a
consumer app. No gradients. No shadows (beyond Simple.css's subtle defaults). No rounded-pill
buttons — Simple.css uses modest `border-radius` by default which is fine.

Dark mode colours (auto-applied via `prefers-color-scheme: dark`):
```css
@media (prefers-color-scheme: dark) {
  :root {
    --accent:       #5ba882;   /* lighter green — readable on dark bg */
    --accent-hover: #6dbf96;
    --accent-bg:    #1a2620;   /* very dark green-tinted surface */
    --text:         #dde8e2;
    --text-light:   #8aaa97;
    --bg:           #141917;
    --border:       #3a4f44;
    --code-bg:      #1f2e27;
  }
}
```

### Typography

Simple.css defaults to the system font stack — no web font download. This is correct for a utility
app: faster, respects the user's system preferences, and degrades gracefully. Do not add a custom
font unless explicitly requested later.

Base font size: Simple.css default (1rem / 16px). Do not reduce it — accessibility requires
at minimum 16px for body text.

### Layout: User-Facing Pages (Login, Register, Reset)

These pages use Simple.css's natural single-column layout centered at ~45rem. No sidebar.
The form sits in the vertical center of the page with the Passage wordmark above it.

```
┌─────────────────────────────────┐
│                                 │
│          passage                │  ← wordmark, text only, --accent color
│                                 │
│  ┌───────────────────────────┐  │
│  │  Sign in to continue      │  │  ← <h2>
│  │                           │  │
│  │  Username                 │  │  ← <label> + <input>
│  │  [________________________│  │
│  │                           │  │
│  │  Password                 │  │
│  │  [________________________│  │
│  │                           │  │
│  │  [    Sign in           ] │  │  ← <button type="submit">
│  │                           │  │
│  │  Forgot password?         │  │  ← <a>
│  │  Create an account        │  │  ← <a> (hidden if registration disabled)
│  └───────────────────────────┘  │
│                                 │
└─────────────────────────────────┘
```

Flash messages (errors, success) render as a Simple.css `<div role="alert">` above the form,
styled via the `--accent` / red palette. No toast popups — inline, above the form.

### Layout: Admin Pages

Admin pages use a two-column layout: a narrow fixed sidebar on the left, content area on the
right. This requires ~25 lines of additional CSS in `passage.css` (Simple.css does not provide
a sidebar layout out of the box).

```
┌──────────────────────────────────────────────────────┐
│  passage admin                              [logout]  │  ← <header>
├──────────┬───────────────────────────────────────────┤
│          │                                           │
│ Dashboard│  Users                          [+ New]   │
│ Users    │  ┌────────────────────────────────────┐   │
│ Apps     │  │ Username  Email       Status  Edit │   │  ← <table>
│ Sessions │  │ alice     a@x.com     active  [✎]  │   │
│ Settings │  │ bob       b@x.com     inactive[✎]  │   │
│          │  └────────────────────────────────────┘   │
└──────────┴───────────────────────────────────────────┘
```

Sidebar navigation uses Simple.css's `<nav>` inside `<aside>`. The current page is indicated via
`aria-current="page"` on the active `<a>` (Simple.css styles this automatically).

Sidebar CSS additions in `passage.css`:
```css
.admin-layout {
  display: grid;
  grid-template-columns: 13rem 1fr;
  grid-template-rows: auto 1fr;
  min-height: 100vh;
}
.admin-layout > header { grid-column: 1 / -1; }
.admin-sidebar { padding: 1rem 0; border-right: 1px solid var(--border); }
.admin-content { padding: 1.5rem 2rem; }
```

### Accessibility Requirements

These are hard requirements, not suggestions:

1. **Keyboard navigable**: Every interactive element reachable and operable via Tab/Enter/Space.
   Simple.css's `:focus-visible` ring satisfies this for standard elements. Custom components
   (flash messages, confirm dialogs) must also carry visible focus state.

2. **Colour contrast**: All text must meet WCAG AA (4.5:1 for normal text, 3:1 for large text).
   The palette above was chosen to satisfy this. Do not introduce new colors without checking
   contrast against the background they appear on.

3. **Semantic HTML**: Use the correct element for the job. `<button>` for actions, `<a>` for
   navigation, `<label for="...">` paired with every input, `<table>` for tabular data with
   `<th scope="col">` headers. Never use `<div>` or `<span>` for interactive elements.

4. **Form labels**: Every `<input>`, `<select>`, and `<textarea>` must have a visible `<label>`.
   No placeholder-only labels — placeholders disappear on input and have insufficient contrast.

5. **Error messages**: Form validation errors must be associated with their field via
   `aria-describedby` pointing to the error element, which carries `role="alert"`.

6. **Page titles**: Every page has a meaningful `<title>` — e.g. `"Sign in — Passage"`,
   `"Users — Passage Admin"`. Not just `"Passage"` on every page.

7. **No motion without preference**: Do not add CSS transitions or animations beyond Simple.css's
   defaults without respecting `prefers-reduced-motion`.

### htmx (Progressive Enhancement)

Ship `htmx.min.js` (~14 KB) in `static/`. Use it only in the admin UI for:
- In-place session revocation (revoke a row without full page reload)
- In-place access grant/revoke on the app access management page
- Potentially: inline flash feedback on form submissions

The UI must be **fully functional without JavaScript** — htmx is an enhancement, not a
dependency. All forms use standard POST. htmx's `hx-post` / `hx-swap` are additive attributes
on forms that already work without them.

Do NOT use htmx for core authentication flows (login, register, reset) — those pages must work
on any browser, including ones with JavaScript disabled.

---

## Project Structure

```
passage/
  cmd/
    passage/
      main.go              # thin: parse flags, call run(), handle error
      run.go               # wires config → db → router → server
  internal/
    config/
      config.go            # load and validate configuration
    db/
      db.go                # open SQLite connection, run migrations
      migrations/          # *.sql files, embedded via embed.FS
        001_initial_schema.sql
    user/
      model.go             # User struct, UserStore interface
      store.go             # SQLite implementation of UserStore
      service.go           # business logic: create, authenticate, reset password
      handler.go           # HTTP handlers for user-facing flows (login, register, reset)
    app/
      model.go             # App struct, AppStore interface
      store.go             # SQLite implementation
      service.go           # business logic: create app, check user access, resolve host
    session/
      model.go             # Session struct, SessionStore interface
      store.go             # SQLite implementation
      service.go           # create, validate, revoke sessions
      middleware.go        # chi middleware: require valid session
    forwardauth/
      handler.go           # /auth/nginx, /auth/traefik, /start, /sign_out endpoints
    admin/
      handler.go           # admin UI HTTP handlers
      middleware.go        # require admin session
    email/
      email.go             # SMTP send helper wrapping go-mail
      templates/           # email body templates (*.html, *.txt), embedded
        password_reset.html
        password_reset.txt
    webauthn/              # Phase 5 — passkey registration/authentication
      handler.go
      store.go
      model.go
      user_adapter.go
      challenge_store.go
    web/
      templates/           # HTML page templates, embedded
        layout.html        # base layout: <head>, wordmark, flash messages
        login.html
        register.html
        reset_request.html
        reset_confirm.html
        profile.html       # passkeys management (Phase 5)
        admin/
          layout.html      # admin layout: sidebar + content area
          dashboard.html
          users.html
          user_form.html
          apps.html
          app_form.html
          app_access.html
          sessions.html
          settings.html
      static/              # CSS, JS, embedded
        simple.min.css     # Simple.css v2.x — classless baseline
        passage.css        # palette overrides + admin sidebar layout (~2 KB)
        htmx.min.js        # htmx for admin progressive enhancement (~14 KB)
        passkey.js         # WebAuthn ceremony JS — Phase 5 only
  go.mod
  go.sum
  passage.example.yaml
  docs/
    nginx-example.conf
    traefik-example.yaml
```

---

## Data Model

### `users`
```sql
CREATE TABLE users (
    id          TEXT PRIMARY KEY,          -- UUIDv4
    username    TEXT UNIQUE NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    password_hash TEXT,                    -- NULL if passkey-only account
    is_admin    INTEGER NOT NULL DEFAULT 0,
    is_active   INTEGER NOT NULL DEFAULT 1,
    -- stub for future RBAC: roles stored as JSON array string, e.g. '["editor"]'
    -- not used in Phase 1 access checks; present to avoid a breaking migration later
    roles       TEXT NOT NULL DEFAULT '[]',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### `apps`
```sql
CREATE TABLE apps (
    id           TEXT PRIMARY KEY,         -- UUIDv4
    slug         TEXT UNIQUE NOT NULL,     -- e.g. "grafana", "homeassistant"
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    -- Glob pattern matched against the incoming Host header.
    -- Supports '*' wildcard, e.g. "grafana.home.example.com" or "*.home.example.com".
    -- A single app may match multiple hostnames via wildcard.
    -- Multiple apps may not have overlapping patterns (enforced at the service layer).
    host_pattern TEXT NOT NULL DEFAULT '',
    is_active    INTEGER NOT NULL DEFAULT 1,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### `user_app_access`
```sql
-- Binary access grant: a row here = this user can access this app.
-- Future: add a 'role' column here for per-app RBAC without a new table.
CREATE TABLE user_app_access (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    -- stub for future per-app roles: e.g. 'viewer', 'editor' — ignored in Phase 1
    role        TEXT NOT NULL DEFAULT 'member',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, app_id)
);
```

### `sessions`
```sql
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,          -- crypto/rand 32-byte hex token
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id      TEXT REFERENCES apps(id) ON DELETE CASCADE, -- NULL = admin/global session
    ip_address  TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);
```

### `password_reset_tokens`
```sql
CREATE TABLE password_reset_tokens (
    token       TEXT PRIMARY KEY,          -- crypto/rand 32-byte hex
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME,                  -- NULL = not yet used
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### `webauthn_credentials` (Phase 3, migration added then)
```sql
CREATE TABLE webauthn_credentials (
    id          TEXT PRIMARY KEY,          -- credential ID, base64url
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL DEFAULT '',  -- user-assigned friendly name
    public_key  BLOB NOT NULL,             -- CBOR-encoded public key
    sign_count  INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME
);
```

### `settings`
```sql
-- Key-value store for runtime-configurable settings.
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Seed values:
-- ('allow_registration', 'true')
-- ('session_duration_hours', '24')
-- ('smtp_from', '')
```

---

## HTTP Endpoint Map

### Forward Auth (consumed by reverse proxy)
| Method | Path | Description |
|---|---|---|
| `GET` | `/auth/nginx` | Nginx `auth_request` check endpoint |
| `GET` | `/auth/traefik` | Traefik `forwardAuth` check endpoint |
| `GET` | `/auth/start` | Redirect to login; `?rd=<return-url>` |
| `POST` | `/auth/sign_out` | Invalidate session cookie |

### User Flows (HTML, browser-facing)
| Method | Path | Description |
|---|---|---|
| `GET` | `/login` | Login page |
| `POST` | `/login` | Submit credentials |
| `GET` | `/register` | Registration page (gated by `allow_registration` setting) |
| `POST` | `/register` | Submit registration |
| `GET` | `/reset` | Request password reset (enter email) |
| `POST` | `/reset` | Submit reset request, send email |
| `GET` | `/reset/:token` | Password reset form (confirm new password) |
| `POST` | `/reset/:token` | Submit new password |
| `GET` | `/logout` | Clear session, redirect to login |

### Admin UI (HTML, requires admin session)
| Method | Path | Description |
|---|---|---|
| `GET` | `/admin` | Dashboard (user count, app count, session count) |
| `GET` | `/admin/users` | User list |
| `GET` | `/admin/users/new` | New user form |
| `POST` | `/admin/users` | Create user |
| `GET` | `/admin/users/:id` | Edit user form |
| `POST` | `/admin/users/:id` | Update user |
| `POST` | `/admin/users/:id/delete` | Delete user |
| `POST` | `/admin/users/:id/reset-password` | Send password reset email |
| `GET` | `/admin/apps` | App list |
| `GET` | `/admin/apps/new` | New app form |
| `POST` | `/admin/apps` | Create app |
| `GET` | `/admin/apps/:id` | Edit app form |
| `POST` | `/admin/apps/:id` | Update app |
| `POST` | `/admin/apps/:id/delete` | Delete app |
| `GET` | `/admin/apps/:id/access` | View/manage user access for app |
| `POST` | `/admin/apps/:id/access` | Grant user access to app |
| `POST` | `/admin/apps/:id/access/:userId/revoke` | Revoke user access |
| `GET` | `/admin/sessions` | Active session list |
| `POST` | `/admin/sessions/:id/revoke` | Revoke a session |
| `GET` | `/admin/settings` | Settings page |
| `POST` | `/admin/settings` | Update settings |

### Utility
| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Health check — `{"status":"ok"}` |

---

## Forward Auth Protocol Detail

The forward-auth endpoints are the core of what makes Passage useful. Both `/auth/nginx` and
`/auth/traefik` implement the same logic; they differ only in how they receive the original
request context:

**Nginx** (`auth_request`) passes:
- `X-Original-URL` header with the full original URL

**Traefik** (`forwardAuth`) passes:
- `X-Forwarded-Host`, `X-Forwarded-Uri`, `X-Forwarded-Proto` headers

**Auth check logic (both endpoints):**
1. Extract the `passage_session` cookie from the request.
2. Look up the session in DB; check it exists, is not expired, and the user is active.
3. Determine the target app from the original host/URL (matched against registered app slugs).
4. Check that the user has access to this app (`user_app_access` row exists).
5. **On success (200):** return empty 200 with identity headers:
   - `X-Passage-Username`
   - `X-Passage-Email`
   - `X-Passage-Name`
   - `X-Passage-User-ID`
   - `X-Passage-Is-Admin`
6. **On failure (401):** return 401 (reverse proxy will redirect to `/auth/start?rd=<url>`).

The `/auth/start` endpoint:
- Saves the `rd` (return URL) in a short-lived cookie or query parameter.
- Redirects to `/login?rd=<url>`.
- After successful login, redirects back to `rd`.

---

## Configuration

Passage is configured via a YAML file and/or environment variables (env vars take precedence).

```yaml
# passage.example.yaml
server:
  host: "0.0.0.0"
  port: 8080
  base_url: "https://auth.home.example.com"   # used for email links, cookie domain

database:
  path: "./passage.db"

session:
  duration_hours: 24
  cookie_name: "passage_session"
  cookie_secure: true      # set false only for local HTTP dev

smtp:
  host: "smtp.example.com"
  port: 587
  username: "passage@example.com"
  password: "secret"
  from: "Passage <passage@example.com>"
  tls: "starttls"          # "starttls", "tls", or "none"

auth:
  allow_registration: true
  bcrypt_cost: 12          # 10-14 recommended; higher = slower = more secure

log:
  level: "info"            # "debug", "info", "warn", "error"
  format: "json"           # "json" or "text"
```

Environment variable mapping: `PASSAGE_SERVER_PORT`, `PASSAGE_DATABASE_PATH`,
`PASSAGE_SMTP_PASSWORD`, etc. (prefix `PASSAGE_`, dots replaced by underscores, uppercased).

---

## Phase 1: Foundation — Core Infrastructure

### Overview
Establishes the project skeleton, database layer, configuration loading, and a running HTTP server
with health check. No auth logic yet — just the plumbing everything else builds on.

### Changes Required:

#### 1. Go module and dependencies
**File**: `go.mod`

Initialize the module and pin all dependencies:
```
module github.com/crueber/passage

go 1.22

require (
    github.com/go-chi/chi/v5 v5.x.x
    github.com/pressly/goose/v3 v3.x.x
    github.com/wneessen/go-mail v0.x.x
    golang.org/x/crypto v0.x.x
    modernc.org/sqlite v1.x.x
)
```

#### 2. Configuration loader
**File**: `internal/config/config.go`

Struct-based config with defaults. Load from YAML file path (passed as `--config` flag) and
override with `PASSAGE_*` env vars. Validate required fields on startup (e.g., `base_url` must
be set, SMTP config validated only if email features are used).

#### 3. Database layer
**Files**: `internal/db/db.go`, `internal/db/migrations/`

- Open SQLite connection via `modernc.org/sqlite`
- Enable WAL mode and foreign keys: `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`
- Run `goose.Up()` at startup using embedded migration files
- `001_initial_schema.sql` — creates all tables defined in the data model above (including the
  `webauthn_credentials` stub table so it exists from day one)

#### 4. HTTP server bootstrap
**Files**: `cmd/passage/main.go`, `cmd/passage/run.go`

- `main.go`: parse `--config` flag, call `run()`, print error and exit 1 on failure
- `run.go`: load config → open DB → build chi router → mount all route groups → start server
- `GET /healthz` returns `{"status":"ok","version":"<build-time version>"}`

#### 5. Structured logging
Use `log/slog` with either JSON or text handler based on config. Pass logger via `context.Context`
or as a dependency on handler structs (consistent with Go conventions — no global logger).

### Success Criteria:

#### Automated Verification:
- [x] `go build ./...` compiles with zero errors, zero warnings
- [x] `go vet ./...` passes
- [x] `CGO_ENABLED=0 go build -o passage ./cmd/passage` produces a binary
- [x] Binary starts: `./passage --config passage.example.yaml`
- [x] Health check: `curl http://localhost:8080/healthz` returns HTTP 200 with `{"status":"ok"}`
- [x] SQLite DB file is created at configured path
- [x] `go test -race ./...` passes

#### Manual Verification:
- [x] Binary starts cleanly, logs are structured JSON
- [x] Stopping with Ctrl-C logs a graceful shutdown message
- [x] Running without a config file starts with defaults (no error — env vars and defaults apply)

**Pause after Phase 1 for manual confirmation before proceeding.**

---

## Phase 2: User Authentication — Login, Register, Password Reset

### Overview
Implements the full user-facing authentication lifecycle: account creation (admin-created and
self-registration), username/password login, session management, and email-based password reset.
Produces a functional login page that a reverse proxy can eventually gate against.

### Changes Required:

#### 1. User store and service
**Files**: `internal/user/model.go`, `internal/user/store.go`, `internal/user/service.go`

- `UserStore` interface (defined in `model.go`, implemented in `store.go`):
  - `Create(ctx, user) error`
  - `GetByID(ctx, id) (*User, error)`
  - `GetByUsername(ctx, username) (*User, error)`
  - `GetByEmail(ctx, email) (*User, error)`
  - `List(ctx) ([]*User, error)`
  - `Update(ctx, user) error`
  - `Delete(ctx, id) error`
- `UserService` (in `service.go`): wraps the store, adds:
  - `Register(ctx, username, email, password) (*User, error)` — hashes password with bcrypt,
    checks `allow_registration` setting, enforces uniqueness
  - `Authenticate(ctx, username, password) (*User, error)` — bcrypt compare, check `is_active`
  - Password reset token generation and validation

#### 2. Session store and service
**Files**: `internal/session/model.go`, `internal/session/store.go`, `internal/session/service.go`

- `SessionStore` interface:
  - `Create(ctx, session) error`
  - `GetByID(ctx, id) (*Session, error)`
  - `ListByUser(ctx, userID) ([]*Session, error)`
  - `Delete(ctx, id) error`
  - `DeleteExpired(ctx) error`
- `SessionService`:
  - `NewSession(ctx, userID, appID, ip, ua) (*Session, error)` — generates 32-byte random token
    via `crypto/rand`, stores with expiry from config
  - `ValidateSession(ctx, token) (*Session, *User, error)` — checks expiry, user active
  - `RevokeSession(ctx, token) error`
- Session cookie: `HttpOnly`, `Secure` (configurable), `SameSite=Lax`, `Path=/`

#### 3. Session middleware
**File**: `internal/session/middleware.go`

chi middleware that:
- Reads the session cookie
- Calls `SessionService.ValidateSession`
- Stores the `*User` in `context.Context`
- Calls `next` if valid; redirects to `/login?rd=<current-url>` if not

#### 4. HTML templates and static assets
**Files**: `internal/web/templates/`, `internal/web/static/`

Pages: `login.html`, `register.html`, `reset_request.html`, `reset_confirm.html`

All extend `layout.html` via `{{block}}` / `{{define}}`. `layout.html` includes:
- `<link rel="stylesheet" href="/static/simple.min.css">`
- `<link rel="stylesheet" href="/static/passage.css">`
- A flash message block rendered above page content (errors/success from cookie)
- `<title>{{block "title" .}} — Passage</title>`

**Visual requirements** (see UI Design Specification above):
- The Passage wordmark (`<h1>passage</h1>` or `<span class="wordmark">passage</span>`) appears
  above the form card in the accent color. Text only — no logo image needed initially.
- Forms are the natural Simple.css width (~45rem centered). No custom card/box styling needed;
  Simple.css's `<main>` container provides it.
- Every `<input>` has a `<label for="...">`. No placeholder-as-label patterns.
- The submit button uses `<button type="submit">` — Simple.css styles it with the accent color.
- Links to register/forgot-password appear below the submit button as plain `<a>` tags.
- Flash messages render as `<div role="alert">` with appropriate styling: error messages use
  a red-tinted border (Simple.css's `--mark-text` / override in `passage.css`), success uses
  the accent green border.

Form submissions use standard HTML POST (no JavaScript required). The `rd` (redirect) parameter
is threaded through as a hidden `<input type="hidden" name="rd" value="{{.RedirectTo}}">` on
the login form so it survives the POST.

#### 5. User-facing HTTP handlers
**File**: `internal/user/handler.go`

- `GET/POST /login` — render form, validate credentials, set session cookie, redirect
- `GET/POST /register` — check `allow_registration` setting, create user, auto-login
- `GET/POST /reset` — render form, create reset token, send email
- `GET/POST /reset/:token` — validate token, render new password form, update password
- `GET /logout` — revoke session, clear cookie, redirect to `/login`

#### 6. Email service
**File**: `internal/email/email.go`

- Wrap `go-mail` with a thin `Sender` interface
- `SendPasswordReset(ctx, toEmail, toName, resetURL) error`
- HTML + plain-text email templates embedded via `embed.FS`
- SMTP config from the global config struct; log and return error if SMTP not configured when
  email is attempted (do not panic)

#### 7. Password reset token store
Inline with the user store (same `store.go` file):
- `CreateResetToken(ctx, userID) (token string, error)`
- `GetResetToken(ctx, token) (*ResetToken, error)`
- `MarkResetTokenUsed(ctx, token) error`

### Success Criteria:

#### Automated Verification:
- [x] `go test -race ./internal/user/...` passes
- [x] `go test -race ./internal/session/...` passes
- [x] `go test -race ./internal/email/...` passes (with SMTP mocked)
- [x] `go build ./...` passes

#### Manual Verification:
- [ ] Navigate to `http://localhost:8080/login` — login page renders
- [ ] Login with wrong password shows error, does not set cookie
- [ ] Login with correct credentials sets `passage_session` cookie, redirects to `/`
- [ ] `GET /logout` clears cookie and redirects to `/login`
- [ ] Self-registration creates a user and logs them in
- [ ] Navigate to `/register` with `allow_registration=false` → redirected to login with error
- [ ] Password reset request with valid email sends email (check SMTP log/mailhog)
- [ ] Password reset token link opens form; new password is accepted; old session is invalidated
- [ ] Expired reset token shows friendly error

**Pause after Phase 2 for manual confirmation before proceeding.**

---

## Phase 3: Forward Auth — Reverse Proxy Integration

### Overview
Implements the forward-auth endpoints that make Passage actually useful. After this phase, Nginx
and Traefik can be configured to call Passage to gate access to any downstream application.
Also implements the `App` model and admin-controlled per-user/app access grants.

### Changes Required:

#### 1. App store and service
**Files**: `internal/app/model.go`, `internal/app/store.go`, `internal/app/service.go`

- `AppStore` interface:
  - `Create(ctx, app) error`
  - `GetByID(ctx, id) (*App, error)`
  - `GetBySlug(ctx, slug) (*App, error)`
  - `List(ctx) ([]*App, error)`
  - `Update(ctx, app) error`
  - `Delete(ctx, id) error`
- Access management (in `store.go` — uses `user_app_access` table):
  - `GrantAccess(ctx, userID, appID) error`
  - `RevokeAccess(ctx, userID, appID) error`
  - `HasAccess(ctx, userID, appID) (bool, error)`
  - `ListUsersWithAccess(ctx, appID) ([]*User, error)`
  - `ListAppsForUser(ctx, userID) ([]*App, error)`

#### 2. App host pattern matching
**File**: `internal/app/service.go`

The forward-auth handler maps the incoming `Host` header (or `X-Forwarded-Host`) to a registered
app. The `host_pattern` column is present from the initial schema (`001_initial_schema.sql`) —
no additional migration is needed.

**Matching strategy: glob with `path.Match` semantics**

Use Go's stdlib `path.Match` (from the `path` package) to evaluate patterns against the
incoming host. This gives users:
- Exact match: `"grafana.home.example.com"` — matches only that host
- Subdomain wildcard: `"*.home.example.com"` — matches any single subdomain label
- Note: `path.Match` does not match path separators with `*`, which is correct for hostnames
  (a `*` matches one label, not `sub.sub.domain`)

`AppService.ResolveFromHost(ctx, host) (*App, error)`:
1. Strip port from host if present (`host:port` → `host`)
2. Load all active apps from DB (small set — cache in memory with 30s TTL or just query each time;
   SQLite is fast enough for home lab scale)
3. Iterate apps; for each, call `path.Match(app.HostPattern, host)`
4. Return the first match; if no match, return `ErrNoAppForHost` (forward-auth returns 401)
5. If multiple apps match the same host, log a warning and return the first match by creation date

**Overlap validation** at the service layer: when an admin creates or updates an app's
`host_pattern`, check it against all existing patterns. Warn (but do not hard-error) if the new
pattern overlaps an existing one — log the conflict clearly so the admin can resolve it.

```go
// Example resolution
apps, _ := appStore.ListActive(ctx)
for _, a := range apps {
    matched, err := path.Match(a.HostPattern, host)
    if err == nil && matched {
        return a, nil
    }
}
return nil, ErrNoAppForHost
```

#### 3. Forward auth handlers
**File**: `internal/forwardauth/handler.go`

```go
type Handler struct {
    sessions session.Service
    apps     app.Service
    config   *config.Config
}
```

`GET /auth/nginx`:
- Read `X-Original-URL` header → extract host
- Read `passage_session` cookie
- `ValidateSession` → get user
- `ResolveFromHost` → get app
- `HasAccess(userID, appID)` → bool
- 200 + identity headers on success; 401 on any failure

`GET /auth/traefik`:
- Same logic; read host from `X-Forwarded-Host` + `X-Forwarded-Proto` + `X-Forwarded-Uri`

`GET /auth/start`:
- Store `rd` param in a signed short-lived cookie (`passage_rd`)
- Redirect to `/login`
- Login handler reads `passage_rd` after successful auth and redirects there

`POST /auth/sign_out`:
- Revoke the current session, clear the cookie, return 200

Identity headers set on 200:
```
X-Passage-Username: <username>
X-Passage-Email:    <email>
X-Passage-Name:     <name>
X-Passage-User-ID:  <uuid>
X-Passage-Is-Admin: <true|false>
```

#### 4. Nginx and Traefik configuration examples
**Files**: `docs/nginx-example.conf`, `docs/traefik-example.yaml`

Provide ready-to-use configuration snippets users can drop into their reverse proxy config.

### Success Criteria:

#### Automated Verification:
- [x] `go test -race ./internal/forwardauth/...` passes
- [x] `go test -race ./internal/app/...` passes (including `TestResolveFromHost_Wildcard`, `TestResolveFromHost_Exact`, `TestResolveFromHost_NoMatch`)
- [x] `go build ./...` passes

#### Manual Verification:
- [ ] Configure Nginx with `auth_request` pointing at `http://localhost:8080/auth/nginx`
- [ ] Unauthenticated request to a protected app → redirected to `/login?rd=<original-url>`
- [ ] After login → redirected back to original URL
- [ ] Identity headers visible to the downstream app (e.g., check via httpbin or echo server)
- [ ] User without app access → 401 (reverse proxy shows access denied, not login page)
- [ ] Revoking a session → next request to protected app triggers re-login
- [ ] Configure Traefik equivalent and verify same behavior

**Pause after Phase 3 for manual confirmation before proceeding.**

---

## Phase 4: Admin UI — User, App, and Session Management

### Overview
Implements the full web-based admin interface. Admins can manage users (create, edit, delete,
send password resets), manage apps (create, edit, delete, manage access grants per app), view and
revoke active sessions, and toggle site-wide settings like `allow_registration`.

### Changes Required:

#### 1. Admin middleware
**File**: `internal/admin/middleware.go`

Chi middleware that requires:
1. A valid session (reuse the session middleware)
2. `user.is_admin == true`

Redirects non-admin users to `/login`. Returns 403 for API clients.

#### 2. Admin handlers
**File**: `internal/admin/handler.go`

One handler struct per domain: `UserHandler`, `AppHandler`, `SessionHandler`, `SettingsHandler`.
All follow the same pattern:

```go
type UserHandler struct {
    users   user.Service
    sessions session.Service
    tmpl    *template.Template
}
```

Handlers use standard HTML forms with POST for all mutations (no JavaScript required for core
function). Flash messages communicated via short-lived signed cookies.

Key non-obvious details:
- **Delete** uses a `<form method="POST" action="/admin/users/:id/delete">` — not HTTP DELETE.
  This keeps the UI functional without JavaScript.
- **Password reset** from admin panel calls `UserService.GenerateResetToken` and
  `EmailService.SendPasswordReset` — same path as self-service reset.
- **App access management**: `/admin/apps/:id/access` shows two lists: users WITH access and users
  WITHOUT. Each entry has a grant/revoke button (form POST).
- **Settings**: read from `settings` table, written back on POST, cached in memory with a short
  TTL (or just re-queried each request — SQLite is fast enough for a home lab).

#### 3. Admin HTML templates
**Files**: `internal/web/templates/admin/`

Pages: `dashboard.html`, `users.html`, `user_form.html`, `apps.html`, `app_form.html`,
`app_access.html`, `sessions.html`, `settings.html`

All extend `admin/layout.html`, which provides:
- The two-column grid layout (sidebar + content) defined in `passage.css`
- A `<header>` spanning both columns with the "passage admin" wordmark and a logout link
- A `<nav>` sidebar with links to Dashboard, Users, Apps, Sessions, Settings
  — `aria-current="page"` set on the active link (Simple.css styles this automatically)
- A flash message block at the top of the content column

**Visual requirements for admin pages:**
- Tables use Simple.css's default `<table>` styling (zebra rows, header background). No custom
  table CSS needed. Columns: keep them few and meaningful — avoid cramming every field.
- Action buttons (Edit, Delete, Revoke) are small secondary buttons inline in table rows.
  Delete and Revoke actions use a `<form method="POST">` with a confirmation `<button>` —
  styled with a muted red border color (override via `passage.css`, ~2 lines) to signal
  destructive intent without being alarming.
- Forms (create/edit) follow Simple.css's natural stacked label-input layout. Field widths
  constrained to ~30rem so they don't stretch across the full content area on wide screens.
- Dashboard shows three stat tiles: total users, total apps, active sessions. Simple CSS grid
  with three equal columns. Each tile is a `<div>` with a large number and a label — no charting
  library, no sparklines.
- The app access page (`app_access.html`) shows two `<table>`s side by side (or stacked on
  narrow): "Users with access" and "Users without access". Each row has a single action button.

**htmx usage in admin templates:**
- Session revoke rows: `hx-post="/admin/sessions/{id}/revoke" hx-target="closest tr" hx-swap="outerHTML"` — replaces the row with a "Revoked" indicator in-place.
- App access grant/revoke: same pattern — row swapped in-place.
- All `hx-*` attributes are additive on forms that also have a standard `action=` and `method=`.
  Removing htmx.min.js from the binary causes graceful fallback to full page reload, no breakage.

#### 4. Session cleanup background task
**File**: `cmd/passage/run.go` (added to the server startup)

A goroutine that calls `SessionStore.DeleteExpired()` every hour. Uses the server's context for
graceful shutdown.

```go
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            if err := sessionStore.DeleteExpired(ctx); err != nil {
                logger.Error("session cleanup failed", "error", err)
            }
        }
    }
}()
```

### Success Criteria:

#### Automated Verification:
- [x] `go test -race ./internal/admin/...` passes
- [x] `go build ./...` passes

#### Manual Verification:
- [ ] `/admin` redirects unauthenticated users to `/login`
- [ ] `/admin` redirects non-admin users to `/` (or shows 403)
- [ ] Admin dashboard shows correct user/app/session counts
- [ ] Create a new user via admin UI — appears in user list
- [ ] Edit a user's name and email — changes persist
- [ ] Delete a user — removed from list; their sessions are also gone (CASCADE)
- [ ] Send password reset email from admin panel — email received
- [ ] Create an app via admin UI — appears in app list
- [ ] Grant user access to app — `/auth/nginx` now returns 200 for that user+app
- [ ] Revoke user access to app — `/auth/nginx` now returns 401
- [ ] Admin sessions list shows all active sessions with IP and UA
- [ ] Revoke a session — that session's cookie is immediately invalid
- [ ] Toggle `allow_registration` off — `/register` returns redirect with error
- [ ] htmx-enhanced session revoke works without full page reload

**Pause after Phase 4 for manual confirmation before proceeding.**

---

## Phase 5: Passkeys (WebAuthn)

### Overview
Adds passkey (WebAuthn) support as an additional credential type. Users can register one or more
passkeys from their profile page and use them as a primary login method. Password-based login
remains fully functional alongside passkeys.

### Changes Required:

#### 1. WebAuthn credential store
**File**: `internal/webauthn/store.go`

- `CredentialStore` interface (defined in `internal/webauthn/model.go`):
  - `Create(ctx, credential) error`
  - `GetByID(ctx, credentialID []byte) (*Credential, error)`
  - `ListByUser(ctx, userID) ([]*Credential, error)`
  - `UpdateSignCount(ctx, credentialID []byte, newCount uint32) error`
  - `Delete(ctx, credentialID []byte) error`
- The `webauthn_credentials` table was created in the initial migration; no new migration needed.

#### 2. User adapter for go-webauthn
**File**: `internal/webauthn/user_adapter.go`

`go-webauthn` requires a `webauthn.User` interface:
```go
type WebAuthnUser struct {
    user        *user.User
    credentials []webauthn.Credential
}
func (u *WebAuthnUser) WebAuthnID() []byte         { return []byte(u.user.ID) }
func (u *WebAuthnUser) WebAuthnName() string       { return u.user.Username }
func (u *WebAuthnUser) WebAuthnDisplayName() string { return u.user.Name }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
```

#### 3. WebAuthn session store (in-memory, short-lived)
**File**: `internal/webauthn/challenge_store.go`

WebAuthn ceremonies require storing a challenge between the browser's registration/auth initiation
and the browser's response. These are short-lived (60 seconds). Store in-memory as a
`sync.Map[sessionID]webauthn.SessionData` with TTL. (SQLite would work too but in-memory is
simpler for 60-second challenges.)

#### 4. WebAuthn HTTP handlers
**File**: `internal/webauthn/handler.go`

Registration flow (requires logged-in user):
- `GET /passkeys/register/begin` → return JSON options for the browser's `navigator.credentials.create()`
- `POST /passkeys/register/finish` → validate response, store credential
- `GET /passkeys` → list user's registered passkeys (with friendly names and last-used)
- `POST /passkeys/:id/delete` → remove a passkey

Authentication flow (no existing session required):
- `GET /login/passkey/begin` → return JSON options for `navigator.credentials.get()`
- `POST /login/passkey/finish` → validate, create session, redirect

#### 5. JavaScript for passkey ceremonies
**File**: `internal/web/static/passkey.js`

Plain JavaScript (no framework). Uses the WebAuthn browser API:
```javascript
// Registration
const options = await fetch('/passkeys/register/begin').then(r => r.json());
const credential = await navigator.credentials.create({ publicKey: options });
await fetch('/passkeys/register/finish', { method: 'POST', body: JSON.stringify(credential) });
```

This is the one place where JavaScript is genuinely required (the WebAuthn browser API is
JavaScript-only). Keep it minimal and self-contained.

#### 6. Login page passkey button
Update `login.html` to add a "Use passkey" button that triggers the authentication ceremony
via `passkey.js`. The password form remains the primary login path; passkeys are an enhancement.

### Success Criteria:

#### Automated Verification:
- [x] `go test -race ./internal/webauthn/...` passes
- [x] `go build ./...` passes

#### Manual Verification:
- [ ] Log in with password, navigate to `/passkeys`
- [ ] Register a passkey (using platform authenticator or hardware key)
- [ ] Log out, click "Use passkey" on login page
- [ ] Passkey authentication succeeds and creates a valid session
- [ ] Delete a passkey from the profile page — it no longer works for login
- [ ] Attempting to use a deleted passkey credential shows a friendly error
- [ ] Passkey list shows friendly name and last-used timestamp
- [ ] Admin can see if a user has passkeys registered (shown in user edit page)

**Pause after Phase 5 for manual confirmation before proceeding.**

---

## Testing Strategy

### Unit Tests (per package)
- `internal/user` — `TestAuthenticate`, `TestRegister_DisabledRegistration`, `TestPasswordReset_*`
- `internal/session` — `TestValidateSession_Expired`, `TestValidateSession_InactiveUser`
- `internal/app` — `TestHasAccess`, `TestResolveFromHost_Exact`, `TestResolveFromHost_Wildcard`,
  `TestResolveFromHost_NoMatch`, `TestResolveFromHost_StripPort`
- `internal/forwardauth` — `TestNginxAuth_ValidSession`, `TestNginxAuth_NoAccess`, `TestNginxAuth_Expired`

### Integration Tests
Use `net/http/httptest` with a real in-memory SQLite database (not mocks):
- Full login → forward-auth → logout cycle
- Password reset email flow
- Admin user creates app, grants access, verifies forward-auth passes

### Test Helpers
```go
// testdb.go (internal/testutil)
func NewTestDB(t *testing.T) *sql.DB {
    t.Helper()
    db, err := sql.Open("sqlite", ":memory:")
    if err != nil { t.Fatal(err) }
    if err := db.RunMigrations(db); err != nil { t.Fatal(err) }
    t.Cleanup(func() { db.Close() })
    return db
}
```

---

## Security Considerations

- **Passwords**: bcrypt with configurable cost (default 12). Minimum password length enforced (8 chars).
- **Session tokens**: 32 bytes from `crypto/rand` → 64-char hex string. Not guessable.
- **Reset tokens**: 32 bytes from `crypto/rand`. Single-use (marked `used_at` on redeem). 1-hour expiry.
- **Cookies**: `HttpOnly`, `Secure` (configurable for local dev), `SameSite=Lax`.
- **CSRF**: All state-changing operations use POST. For Phase 1-4, the `SameSite=Lax` cookie
  attribute provides CSRF protection for top-level navigations. If stricter CSRF protection is
  needed later, a token-per-form approach can be added without breaking changes.
- **Admin routes**: Separate middleware; `is_admin` checked on every request (not cached in session).
- **SQL injection**: All queries use parameterized statements via `database/sql`.
- **XSS**: `html/template` auto-escaping on all rendered output.
- **Rate limiting**: Not in initial scope — can be added as chi middleware later.
- **Initial admin setup**: On first run (empty DB), if no admin user exists, log a one-time setup
  token to stdout that allows creating the first admin user via `/setup` endpoint (disabled once
  an admin exists).

---

## Future Extensibility Hooks

These are NOT implemented but are intentionally designed for in the data model and structure:

| Feature | Extensibility Hook |
|---|---|
| OAuth2 providers | Add `oauth_accounts` table linking `user_id` to provider + provider_user_id. Add provider config to YAML. Mount new `/auth/oauth/:provider` routes. |
| Per-app RBAC | `role` column already in `user_app_access`. Add `ListAppsForUserWithRole`. Update forward-auth to include `X-Passage-Role` header. |
| Group-based access | Add `groups` and `user_groups` tables. `HasAccess` checks group membership as fallback. |
| Audit log | Add `audit_events` table. Wrap service calls to emit events. |
| Rate limiting | Add chi middleware before route groups. `golang.org/x/time/rate` is pure Go. |

---

## References

- Forward auth pattern research: (see planning session)
- Go library research: (see planning session)
- Authentik docs (reference for forward-auth protocol): https://docs.goauthentik.io/docs/providers/proxy/
- WebAuthn spec: https://www.w3.org/TR/webauthn-3/
- go-webauthn library: https://github.com/go-webauthn/webauthn
- modernc SQLite (pure Go): https://gitlab.com/cznic/sqlite
