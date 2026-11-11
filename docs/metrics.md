# Metrics

Passage exposes Prometheus metrics at `GET /metrics` in the text exposition
format (`text/plain; version=0.0.4`). The endpoint is enabled by default.

## Configuration

```yaml
metrics:
  # Serve GET /metrics. Set to false to make the endpoint answer 404.
  enabled: true
  # Optional. When set, every scrape must send
  # "Authorization: Bearer <token>". Leave empty when the endpoint is only
  # reachable from a trusted network or an authenticating proxy.
  token: ""
```

| Environment variable | Meaning |
|---|---|
| `PASSAGE_METRICS_ENABLED` | `true`/`false`; same as `metrics.enabled` |
| `PASSAGE_METRICS_TOKEN` | same as `metrics.token` |

The token is compared in constant time, is never logged or echoed, and may not
contain whitespace or control characters (a Bearer credential cannot carry
them). An unauthenticated scrape receives `401` with
`WWW-Authenticate: Bearer realm="metrics"`.

`metrics.enabled: false` answers `404 Not Found`, exactly as if the route did
not exist, so a disabled endpoint does not advertise itself.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `passage_auth_events_total` | counter | `event`, `outcome` | Every authentication event written to the security log |
| `passage_sessions_created_total` | counter | — | Sessions created since process start |
| `passage_sessions_revoked_total` | counter | — | Explicit session revokes since process start |
| `passage_http_requests_total` | counter | `method`, `status` | Every HTTP request, by method and response status code |
| `passage_users` | gauge | — | User accounts, including inactive ones |
| `passage_apps` | gauge | — | Applications, including inactive ones |
| `passage_active_sessions` | gauge | — | Sessions that have not passed their absolute expiry |
| `passage_process_start_time_seconds` | gauge | — | Process start time since the Unix epoch |
| `passage_build_info` | gauge | `version` | Always `1`; the version is the build-time `-ldflags` value |

### Semantics

- `passage_auth_events_total` counts the same events the admin security log
  records (`login.success`, `passkey.failure`, `mfa.success`, `oauth.token`,
  …). The `event` label values are exactly `authlog.Names()`, and `outcome` is
  one of `success`, `failure`, `throttled` (empty for events that have no
  outcome). Counting happens even if the log write itself failed: the event
  happened.
- `passage_sessions_created_total` increments after the session row is written,
  so a failed sign-in never counts.
- `passage_sessions_revoked_total` counts **revoke operations**, not rows: a
  single-session revoke counts once, a "sign out everywhere" counts once
  regardless of how many sessions it removed, and expiry or idle sweeps are not
  revokes at all.
- `passage_http_requests_total` labels only the method and the status code.
  Paths are never recorded, so the label set stays bounded no matter what
  clients request. The method is upper-cased and an unknown or extension method
  is bucketed as `other`. A request is counted when it finishes, so it first
  appears in the next scrape. Requests that panic are counted with the `500`
  the recoverer writes.
- `passage_active_sessions` does not apply the idle timeout: an idle session is
  rejected when it is used, not deleted from the table.

### Cost

A scrape runs three `COUNT(*)` queries (`users`, `apps`, `sessions`) on the
existing connection and reads the counters from memory. The response is
gathered before it is written, and no lock or database connection is held while
the exposition is rendered, so a slow or concurrent scrape never blocks a login
or a forward-auth request. A gauge whose query fails is logged and omitted for
that scrape rather than published as a misleading zero.

## Prometheus

```yaml
scrape_configs:
  - job_name: passage
    metrics_path: /metrics
    # Only needed when metrics.token is set.
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/passage-metrics-token
    static_configs:
      - targets: ["auth.home.example.com"]
```

Useful starting queries:

```promql
# Logins per minute by outcome
sum by (outcome) (rate(passage_auth_events_total{event="login.success"}[5m]))

# 5xx rate
sum(rate(passage_http_requests_total{status=~"5.."}[5m]))
  / sum(rate(passage_http_requests_total[5m]))

# Active sessions
passage_active_sessions
```

## Design notes

`internal/metrics` is a dependency-free registry: atomic counters with an
ordered label set, gauges as callbacks, and a text encoder that sorts families
by name and samples by label values, so two scrapes of unchanged data are
byte-identical. There are no histograms — everything Passage publishes is a
counter or a gauge. Instrumentation is best-effort: recording a metric never
fails, delays, or changes an authentication flow.
