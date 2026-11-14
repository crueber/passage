# Administrative REST API

Passage exposes a small, read-only JSON API for operators and automation. It
answers questions — who is signed in, which apps exist, what happened in the
audit log — and never changes state. Anything that mutates Passage stays in the
admin UI.

```
GET /api/v1/whoami
GET /api/v1/users
GET /api/v1/users/{id}
GET /api/v1/apps
GET /api/v1/apps/{id}
GET /api/v1/sessions
GET /api/v1/audit?page=1&limit=50
```

## Authentication

Every request needs a bearer token, created in the admin UI under
**System → API tokens** (`/admin/api-tokens`):

```bash
curl -H "Authorization: Bearer pst_…" https://passage.example.com/api/v1/users
```

- The token format is `pst_` followed by 32 bytes of `crypto/rand`, encoded as
  unpadded base64url (43 characters). The plaintext is shown **exactly once**
  when it is created.
- Only the SHA-256 hex digest is stored. A copy of the SQLite file therefore
  does not yield usable tokens, and a lost token cannot be recovered — revoke it
  and mint another.
- A token is an administrator credential: it can read every user record, every
  app, and every active session. Treat it like a password and keep it out of
  shell history where you can.
- There are no scopes. Every token is read-only, because the whole API is.
- A missing, malformed, unknown, or revoked token returns `401` with
  `WWW-Authenticate: Bearer`. The response does not say which of those it was.
- Failed bearer authentication is recorded in the security log as
  `api.auth_failure`. Successful calls are not logged (a poller would drown the
  log); `last_used_at` is updated on the token instead.

Requests are rate limited per client IP (120 requests per minute), sharing the
in-memory sliding-window limiter used elsewhere in Passage. Over the limit the
API answers `429` with `Retry-After`.

## Response conventions

- `Content-Type: application/json`.
- Every timestamp is UTC RFC 3339 (`2006-01-02T15:04:05Z`). Optional times are
  `null`, never an empty string.
- Collection endpoints wrap their rows in a named array (`users`, `apps`,
  `sessions`, `events`). Single-resource endpoints return the object directly.
- Errors are `{"error": "not found"}` — a stable `error` field, nothing else.
- Missing resources return `404`.
- No response ever contains a password hash, a client secret hash, a session
  ID, or a token. Sessions are identified by their non-secret `public_id`.

## Endpoints

### `GET /api/v1/whoami`

Identifies the calling token, useful as a connectivity check.

```json
{
  "id": "0f0a…",
  "name": "grafana exporter",
  "scope": "read-only",
  "created_at": "2026-11-11T09:12:00Z",
  "last_used_at": "2026-11-11T09:30:00Z"
}
```

`last_used_at` is updated best-effort on every authenticated request, so it
includes the call that fetched this response. A write failure is logged and does
not fail the request.

### `GET /api/v1/users` and `GET /api/v1/users/{id}`

```json
{
  "users": [
    {
      "id": "e0d8…",
      "username": "alice",
      "email": "alice@example.com",
      "name": "Alice Example",
      "is_admin": true,
      "is_active": true,
      "email_verified": true,
      "created_at": "2026-01-04T10:00:00Z",
      "updated_at": "2026-11-01T18:22:41Z"
    }
  ]
}
```

### `GET /api/v1/apps` and `GET /api/v1/apps/{id}`

```json
{
  "apps": [
    {
      "id": "7c2e…",
      "slug": "grafana",
      "name": "Grafana",
      "description": "Dashboards",
      "host_pattern": "grafana.example.com",
      "default_url": "https://grafana.example.com",
      "is_active": true,
      "session_duration_hours": 0,
      "oauth_enabled": true,
      "client_id": "passage-grafana",
      "created_at": "2026-02-14T08:00:00Z",
      "updated_at": "2026-10-30T12:00:00Z"
    }
  ]
}
```

`client_id` is the public OAuth client identifier, not a secret;
`client_secret_hash` is never exposed. `session_duration_hours: 0` means the app
uses the global session duration.

### `GET /api/v1/sessions`

Active (non-expired) sessions, newest first.

```json
{
  "sessions": [
    {
      "public_id": "9b1f…",
      "user_id": "e0d8…",
      "username": "alice",
      "app_id": null,
      "ip_address": "192.0.2.10",
      "user_agent": "Mozilla/5.0 …",
      "created_at": "2026-11-11T08:00:00Z",
      "last_used_at": "2026-11-11T09:29:12Z",
      "expires_at": "2026-11-12T08:00:00Z"
    }
  ]
}
```

`app_id` is `null` for a global (admin) session and the app's ID for an
app-scoped session. This endpoint is read-only: revoking a session is an admin
UI action.

### `GET /api/v1/audit?page=1&limit=50`

Administrative audit events, newest first. `limit` defaults to 50 and is capped
at 500; `page` is 1-based. Invalid values fall back to the defaults rather than
erroring, and out-of-range pages return an empty array.

```json
{
  "events": [
    {
      "id": "4a55…",
      "actor_id": "e0d8…",
      "actor_name": "alice",
      "action": "api_token.create",
      "target_type": "api_token",
      "target_id": "0f0a…",
      "target_name": "grafana exporter",
      "detail": "",
      "ip_address": "198.51.100.7",
      "created_at": "2026-11-11T09:12:00Z"
    }
  ],
  "page": 1,
  "limit": 50
}
```

## Managing tokens

The admin page lists every token with its name, creation time, last use, and
state (Active / Revoked). Revoking takes effect immediately: the next request
with that token gets a `401`. Revoked tokens are kept in the table so the
history stays readable; the row is never deleted.

Token creation and revocation are audited as `api_token.create` and
`api_token.revoke`, and both actions appear in the admin log filter.

## Notes for operators

- A token stopping with `401` while `last_used_at` does not advance usually
  means it was revoked, or (less likely) the request never reached Passage.
- `429` means the per-IP window is full; `Retry-After` says how long to wait.
- The API is served by the same process and the same SQLite connection as the
  UI. It is intentionally small: use the UI for anything that writes.
