# Passage

A self-hosted authentication proxy for home labs — implements the forward-auth pattern so that Nginx, Traefik, or Caddy can delegate authentication decisions to a single, lightweight service.

## What it does

- **Username/password login** with bcrypt-hashed credentials stored in a local SQLite database
- **Passkey support** (WebAuthn) for passwordless authentication on supporting browsers and devices
- **Admin web UI** for managing users and protected applications
- **SQLite backing store** — a single file, no separate database server required
- **Single static binary** — no runtime dependencies, no CGo, deploy anywhere Go runs

## Status

Early development — pre-release. Not yet suitable for production use. APIs and configuration format may change without notice.

## Quick Start

Documentation is coming. For now, see the `plans/` directory for implementation progress and the `docs/` directory for reverse proxy configuration examples.

## Configuration

Documentation is coming. Configuration is loaded from environment variables with an optional YAML file override. See `config.example.yaml` (when available) for all supported options.

## Reverse Proxy Setup

### Nginx

Documentation is coming. Passage exposes a `/auth/nginx` endpoint compatible with Nginx's `auth_request` module.

### Traefik

Documentation is coming. Passage exposes a `/auth/traefik` endpoint compatible with Traefik's ForwardAuth middleware.

## Development

Requirements: Go 1.22+, no CGo required.

```bash
git clone git@github.com:crueber/passage.git
cd passage
go build ./...
go test -race ./...
```

## License

MIT — see [LICENSE](LICENSE)
