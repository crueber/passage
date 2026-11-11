# Per-app access policies

Access to an app can be narrowed beyond "this user has been granted the app".
Each app carries an optional policy made of six rules: a required group, a
required role, an IP range list, an admin-only flag, an allowed-hours window and
an allowed-days list. Every rule is optional; an app with none set behaves
exactly as it did before policies existed.

Policies are enforced in two places:

- **Forward-auth** (`/auth/nginx`, `/auth/traefik`): a denial is `403 Forbidden`
  with a generic `Access denied` body. The upstream app is never reached and no
  `X-Passage-*` identity headers are set.
- **OAuth / OIDC authorize** (`/oauth/authorize`): a denial is the standard
  `access_denied` error with the fixed description
  `The resource owner or authorization server denied the request.` No
  authorization code is issued.

The dashboard (`/`) deliberately does **not** apply policies: a launch link may
still be listed even when the app would refuse a forwarded request right now
(for example outside its allowed hours).

## Rules

A user must already have access to the app (`user_app_access`); the policy only
narrows that grant. All configured rules must pass — they combine with `AND`.

| Field | Meaning |
|---|---|
| `required_group` | The user must effectively hold this app-scoped group, directly or inherited through a role they hold. Matched case-insensitively, surrounding whitespace ignored. |
| `required_role` | The user must hold this app-scoped role. |
| `allowed_cidrs` | Comma or space separated CIDR prefixes, IPv4 (`192.168.0.0/16`) or IPv6 (`2001:db8::/32`). The request's client address must fall inside one of them. |
| `admin_only` | Only users with the admin flag may use the app. |
| `allowed_hours` | One `HH:MM-HH:MM` window in **server local time**. Both endpoints are inclusive; `22:00-06:00` wraps past midnight; equal endpoints mean the whole day. |
| `allowed_days` | ISO weekdays, `1` = Monday … `7` = Sunday. Comma list and ascending ranges are accepted, e.g. `1-5` or `6,7`. |

Admins are **not** exempt from the rules. `admin_only` adds a requirement; it
does not bypass a CIDR or hour window. An app that should be admin-only and
reachable from anywhere sets only `admin_only`.

The client address is the one the forward-auth request or authorize request
arrived from. Passage applies chi's `RealIP` middleware, so behind a reverse
proxy this is the address in `X-Forwarded-For` / `X-Real-IP` — configure those
headers only from trusted proxies, or the CIDR rule can be spoofed. With no
reverse proxy in front, it is the direct peer address.

## Evaluation order

`internal/policy` is pure — no database, no HTTP — and evaluates in this order
so the recorded reason is deterministic:

1. `admin_only`
2. `required_group`
3. `required_role`
4. `allowed_cidrs`
5. `allowed_days`
6. `allowed_hours`

The first rule that fails produces the denial reason: `admin_only`, `group`,
`role`, `client_ip`, `days` or `hours`.

An unparseable stored rule, or a request whose client address cannot be parsed
while CIDRs are configured, **fails closed** (denied). The handler logs the
error; the client still sees the generic denial.

## Configuration

Admins set the policy on the app's details page in the admin UI
(**Apps → app → Access policy**). Fields are validated on save:

- CIDRs must parse as prefixes (`netip.ParsePrefix`).
- Hours must be `HH:MM-HH:MM` with a valid 24-hour clock.
- Days must be ISO weekday numbers or ascending ranges.

Invalid input re-renders the form with an error and nothing is saved. Leaving
every field empty saves a policy that imposes no restriction; you can also clear
a policy by emptying the fields.

Stored columns (migration `021_app_access_policies`), all additive with a
"no restriction" default:

```
apps.required_group  TEXT    NOT NULL DEFAULT ''
apps.required_role   TEXT    NOT NULL DEFAULT ''
apps.allowed_cidrs   TEXT    NOT NULL DEFAULT ''
apps.admin_only      INTEGER NOT NULL DEFAULT 0
apps.allowed_hours   TEXT    NOT NULL DEFAULT ''
apps.allowed_days    TEXT    NOT NULL DEFAULT ''
```

## Events

A policy denial records an `access.denied` authentication event with
`outcome=failure`, the username, the client address, and a detail of the form
`app=<slug> reason=<rule>`. It never contains a credential, token or response
body. The same detail is written to the server log at info level for forward-auth
and for OAuth authorize.

## Related

- [Forward-auth integration](forward-auth.md)
- [Security model](security.md)
