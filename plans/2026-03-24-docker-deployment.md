# Passage — Docker & CI/CD Deployment Plan

## Overview

Package the Passage binary as a minimal production Docker image, publish it to GitHub Container
Registry (GHCR) via a GitHub Actions CI/CD pipeline, and provide a ready-to-use Docker Compose
setup for self-hosters. This plan covers everything from the `Dockerfile` through the Traefik
integration example — nothing more.

---

## Current State Analysis

- All five implementation phases are complete. The binary builds cleanly with `CGO_ENABLED=0`.
- `go.mod` declares **Go 1.25.0**; the module is `github.com/crueber/passage`.
- Version is injected at link time via `-ldflags "-X main.version=<value>"` — the variable
  `version` lives in `cmd/passage/run.go`.
- Health check endpoint is live at `GET /healthz` — returns `{"status":"ok","version":"..."}` with
  HTTP 200. Ideal for `HEALTHCHECK` and Docker Compose.
- Config is loaded from a YAML file **or** from `PASSAGE_*` environment variables, so the image
  can be configured entirely via env vars without mounting a config file.
- The SQLite database path defaults to `passage.db` (relative); in a container it must be an
  absolute path inside a named volume (e.g. `/data/passage.db`).
- SMTP uses STARTTLS by default (`smtp.tls: starttls`). The TLS handshake requires trusted CA
  certificates, which means a distroless-static image (no CA bundle) would break SMTP. Alpine or
  distroless-base (which includes CA certs) are the correct runtime targets.
- No `Dockerfile`, `.dockerignore`, `.github/`, or `docker-compose.yml` exist yet.
- The existing `docs/` directory already has `nginx-example.conf` and `traefik-example.yaml`; the
  Traefik Docker Compose example will live there as `docs/traefik-compose-example.yml`.

### Key `PASSAGE_*` Environment Variables

| Variable | Maps to |
|---|---|
| `PASSAGE_SERVER_HOST` | `server.host` |
| `PASSAGE_SERVER_PORT` | `server.port` |
| `PASSAGE_SERVER_BASE_URL` | `server.base_url` |
| `PASSAGE_DATABASE_PATH` | `database.path` |
| `PASSAGE_SESSION_DURATION_HOURS` | `session.duration_hours` |
| `PASSAGE_SESSION_COOKIE_NAME` | `session.cookie_name` |
| `PASSAGE_SESSION_COOKIE_SECURE` | `session.cookie_secure` |
| `PASSAGE_SMTP_HOST` | `smtp.host` |
| `PASSAGE_SMTP_PORT` | `smtp.port` |
| `PASSAGE_SMTP_USERNAME` | `smtp.username` |
| `PASSAGE_SMTP_PASSWORD` | `smtp.password` |
| `PASSAGE_SMTP_FROM` | `smtp.from` |
| `PASSAGE_SMTP_TLS` | `smtp.tls` |
| `PASSAGE_AUTH_ALLOW_REGISTRATION` | `auth.allow_registration` |
| `PASSAGE_AUTH_BCRYPT_COST` | `auth.bcrypt_cost` |
| `PASSAGE_LOG_LEVEL` | `log.level` |
| `PASSAGE_LOG_FORMAT` | `log.format` |

---

## Desired End State

After all three phases are complete:

1. `docker build -t passage:local .` produces a working image under 20 MB.
2. `docker run --rm -e PASSAGE_SERVER_BASE_URL=http://localhost:8080 -e PASSAGE_DATABASE_PATH=/data/passage.db -v /tmp/passage-data:/data -p 8080:8080 passage:local` starts the server and `curl http://localhost:8080/healthz` returns `{"status":"ok","version":"dev"}`.
3. `docker compose up` using the repo-root `docker-compose.yml` starts Passage fully configured.
4. Pushing a `v*` tag to GitHub creates a multi-arch GHCR image tagged with the semver version.
5. `ghcr.io/crueber/passage:latest` is always the HEAD of `main`.

---

## What We Are NOT Doing

- No Kubernetes manifests or Helm charts (not in scope).
- No Docker Swarm configs (not in scope).
- No Let's Encrypt / TLS termination inside the Passage container — that is the reverse proxy's job.
- No multi-user secrets management (Vault, Doppler, etc.) — `.env` file is sufficient for a
  self-hosted home lab.
- No separate build caching service (BuildKit inline cache is enough).
- No automated semantic versioning or changelog generation.
- No self-updating mechanism inside the container.

---

## Implementation Approach

Three tightly-scoped phases:

1. **Dockerfile + .dockerignore** — the core build artifact.
2. **GitHub Actions CI/CD workflow** — automated testing, building, and publishing.
3. **Docker Compose + Traefik example** — self-hosting documentation for end users.

Each phase is independently verifiable and can be committed separately.

---

## Phase 1: Dockerfile and .dockerignore

### Overview

Produce a minimal, secure Docker image using a multi-stage build:

- **Stage 1 (`builder`)**: Uses the official `golang:1.25-alpine` image to compile the binary with
  `CGO_ENABLED=0 GOOS=linux`. The git tag and SHA are injected via `-ldflags`.
- **Stage 2 (`final`)**: Uses `alpine:3.21` as the runtime. Alpine is preferred over distroless for
  this project because:
  - SMTP with STARTTLS/TLS requires CA certificates (`ca-certificates` package). Distroless-static
    has no CA bundle; distroless-base does have it but ships glibc which is irrelevant here.
  - Alpine ships `wget` (needed for a `HEALTHCHECK` shell command) and allows adding a
    non-root user trivially.
  - Image size is ~5 MB base + binary, well under 20 MB.
  - Security updates are fast and the package ecosystem is familiar to home-lab operators.
- The binary runs as a non-root user (`passage`, uid 1000).
- `/data` is declared as a `VOLUME` so the SQLite file is never stored inside the writable layer.
- `EXPOSE 8080` documents the port; actual binding is via `docker run -p` or Compose.

### Changes Required

#### 1. `Dockerfile`

**File**: `Dockerfile`

```dockerfile
# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Build
# ─────────────────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# Install git so `go build` can embed VCS info (used by go-webauthn and goose).
RUN apk add --no-cache git

WORKDIR /src

# Download dependencies first (layer cached until go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a fully static binary.
COPY . .

# Build arguments allow the CI pipeline to inject version metadata.
ARG VERSION=dev
ARG GIT_SHA=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} \
    go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/passage \
      ./cmd/passage

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Runtime
# ─────────────────────────────────────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates: required for SMTP TLS / STARTTLS connections.
# tzdata: optional but prevents timezone warnings from some libraries.
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 -h /home/passage passage

# Declare a volume for the SQLite database so it is never stored in the
# writable container layer. Operators must mount a persistent volume here.
VOLUME ["/data"]

WORKDIR /home/passage

COPY --from=builder /out/passage /usr/local/bin/passage

# Health check via the /healthz endpoint.
# start_period gives Passage time to run migrations on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

USER passage

EXPOSE 8080

# Default: no config file — configure entirely via PASSAGE_* env vars.
# Set PASSAGE_DATABASE_PATH to a path under /data, e.g. /data/passage.db.
ENTRYPOINT ["/usr/local/bin/passage"]
```

#### 2. `.dockerignore`

**File**: `.dockerignore`

```
# Build artifacts
/passage
/passage.exe
dist/

# Database files — never bake the DB into the image
*.db
*.db-shm
*.db-wal

# Test artifacts
*.test
*.out
coverage.out

# Go module download cache
vendor/

# Editor and IDE metadata
.DS_Store
.idea/
.vscode/
*.swp
*.swo
*~

# Git internals (not needed by go build)
.git/
.gitignore
.worktrees/

# CI/CD and local tooling
.github/
.golangci-lint-cache/
tmp/

# Docker files themselves (avoid redundant COPY)
Dockerfile
.dockerignore
docker-compose*.yml
.env
*.env.local
.env.*

# Documentation and plans (not needed in the binary)
docs/
plans/
README.md
LICENSE
passage.example.yaml
```

### Success Criteria

#### Automated Verification
- [ ] Image builds successfully: `docker build -t passage:local .`
- [ ] Image size is under 20 MB: `docker image inspect passage:local --format '{{.Size}}'` (value should be < 20971520)
- [ ] Container starts and passes health check:
  ```bash
  docker run -d --name passage-test \
    -e PASSAGE_SERVER_BASE_URL=http://localhost:8080 \
    -e PASSAGE_DATABASE_PATH=/data/passage.db \
    -v /tmp/passage-test-data:/data \
    -p 8080:8080 \
    passage:local
  sleep 5
  curl -sf http://localhost:8080/healthz
  docker rm -f passage-test
  ```
- [ ] `/healthz` returns `{"status":"ok",...}` with HTTP 200
- [ ] Binary runs as non-root: `docker run --rm passage:local id` shows uid=1000(passage)
- [ ] No CGo in binary: `docker run --rm --entrypoint file passage:local /usr/local/bin/passage` shows `statically linked`
- [ ] `.dockerignore` is present and `*.db` files are excluded: verify no `.db` files appear in `docker run --rm passage:local ls /home/passage`

#### Manual Verification
- [ ] `docker build` output shows two stages completing cleanly with no warnings
- [ ] The image does NOT contain any source code (verify with `docker run --rm passage:local ls /src` — should fail)
- [ ] Confirm `passage.example.yaml` is not baked into the image

**Implementation Note**: After completing Phase 1 and all automated checks pass, pause here and confirm manually that the image behaves as expected before proceeding to Phase 2.

---

## Phase 2: GitHub Actions CI/CD Workflow

### Overview

Create a single GitHub Actions workflow file that:

1. Runs `go test -race ./...` on every push and pull request (as a gate).
2. Builds and pushes a multi-arch Docker image (`linux/amd64`, `linux/arm64`) to GHCR on:
   - Push to `main` → tag `latest` and `main-<short-sha>`.
   - Push of a `v*` tag → tag `v1.2.3`, `v1.2`, `v1`, and `latest`.
3. Does **not** push images on pull requests — tests only.
4. Uses `GITHUB_TOKEN` for GHCR authentication — no personal access token required.
5. Injects the git tag/SHA as the binary version via `--build-arg VERSION=...`.

### Changes Required

#### 1. Workflow directory

**File**: `.github/workflows/ci.yml`

```yaml
name: CI / Publish

on:
  push:
    branches:
      - main
    tags:
      - "v*"
  pull_request:
    branches:
      - main

permissions:
  contents: read
  packages: write   # required to push to GHCR

jobs:
  # ─────────────────────────────────────────────────────────────────────────
  # Job 1: Test — runs on every push and every PR
  # ─────────────────────────────────────────────────────────────────────────
  test:
    name: Test
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Verify dependencies
        run: go mod verify

      - name: go vet
        run: go vet ./...

      - name: Run tests (with race detector)
        run: go test -race ./...

  # ─────────────────────────────────────────────────────────────────────────
  # Job 2: Publish — runs only on push to main or v* tag (not PRs)
  # ─────────────────────────────────────────────────────────────────────────
  publish:
    name: Build & Publish Image
    runs-on: ubuntu-latest
    needs: test
    if: github.event_name == 'push'   # skip on pull_request events

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          # Fetch full history so `git describe` works for version injection.
          fetch-depth: 0

      - name: Determine version
        id: version
        run: |
          # On a tag push, VERSION = the tag (e.g. v1.2.3).
          # On a branch push, VERSION = <branch>-<short-sha>.
          if [[ "${GITHUB_REF}" == refs/tags/* ]]; then
            VERSION="${GITHUB_REF_NAME}"
          else
            VERSION="${GITHUB_REF_NAME}-$(git rev-parse --short HEAD)"
          fi
          echo "version=${VERSION}" >> "$GITHUB_OUTPUT"
          echo "sha=$(git rev-parse --short HEAD)" >> "$GITHUB_OUTPUT"

      - name: Set up QEMU (for cross-compilation)
        uses: docker/setup-qemu-action@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract Docker metadata (tags and labels)
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/crueber/passage
          tags: |
            # On v* tags: publish semver tags (v1.2.3, v1.2, v1) + latest
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}
            # On main branch: publish "latest" + "main-<sha>"
            type=raw,value=latest,enable={{is_default_branch}}
            type=sha,prefix=main-,enable={{is_default_branch}}

      - name: Build and push multi-arch image
        uses: docker/build-push-action@v6
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          build-args: |
            VERSION=${{ steps.version.outputs.version }}
            GIT_SHA=${{ steps.version.outputs.sha }}
          # Inline BuildKit cache — no external cache service required.
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

### Notes on Design Decisions

- **`actions/setup-go` with `go-version-file: go.mod`** — always uses the exact Go version
  declared in `go.mod` (currently 1.25.0); no manual version pinning needed.
- **`fetch-depth: 0`** — the full history allows `git describe --tags` to work, which is used
  for the version string on branch builds.
- **`docker/metadata-action`** — handles all tag generation logic cleanly. On `v1.2.3` it
  produces `v1.2.3`, `v1.2`, `v1`, and `latest`. On `main` it produces `latest` and
  `main-<sha>`.
- **`cache-from/cache-to: type=gha`** — uses GitHub Actions cache as the BuildKit layer cache.
  Free, no external service, works well with multi-arch builds.
- **`permissions: packages: write`** — required for `GITHUB_TOKEN` to push to GHCR.
  `contents: read` is the minimal read permission.
- **`if: github.event_name == 'push'`** — the `publish` job is skipped for `pull_request`
  events, so forked PRs cannot trigger a push.

### Success Criteria

#### Automated Verification
- [ ] Workflow YAML is syntactically valid: `docker run --rm -v $(pwd):/repo rhysd/actionlint:latest /repo/.github/workflows/ci.yml` (or use the GitHub Actions linter)
- [ ] The `test` job runs on a PR and does **not** trigger the `publish` job
- [ ] The `test` job runs on a push to `main` and **does** trigger the `publish` job
- [ ] Image appears at `ghcr.io/crueber/passage:latest` after a push to `main`
- [ ] Image has both `linux/amd64` and `linux/arm64` manifests:
  ```bash
  docker buildx imagetools inspect ghcr.io/crueber/passage:latest
  ```
- [ ] After pushing `v0.1.0` tag, image is available at `ghcr.io/crueber/passage:v0.1.0`,
      `ghcr.io/crueber/passage:v0.1`, and `ghcr.io/crueber/passage:v0`
- [ ] `/healthz` on the published image returns the correct version string (not `dev`):
  ```bash
  docker run --rm \
    -e PASSAGE_SERVER_BASE_URL=http://localhost:8080 \
    -e PASSAGE_DATABASE_PATH=/data/passage.db \
    -v /tmp/passage-ci-test:/data \
    -p 8080:8080 \
    ghcr.io/crueber/passage:latest &
  sleep 5 && curl -sf http://localhost:8080/healthz
  ```

#### Manual Verification
- [ ] Open the Actions tab in the GitHub repository and confirm the `CI / Publish` workflow
      appears and runs green on the first push after adding the file
- [ ] Confirm the GHCR package page shows the image as public (or adjust visibility in GitHub
      Package settings if it defaults to private)
- [ ] Pull the `linux/arm64` image on an Apple Silicon Mac or Raspberry Pi and confirm
      it starts: `docker run --rm --platform linux/arm64 ghcr.io/crueber/passage:latest --help`

**Implementation Note**: After Phase 2 passes all automated checks and the first image is
successfully published to GHCR, pause here for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Docker Compose and Traefik Integration Example

### Overview

Provide two Compose files for self-hosters:

1. **`docker-compose.yml`** (repo root) — standalone Passage deployment. Uses env vars from a
   `.env` file for secrets. Named volume for the SQLite database. Health check and restart policy.
   Suitable for users who already have a reverse proxy on the host.

2. **`docs/traefik-compose-example.yml`** — a complete example showing Passage integrated with
   Traefik v3 as the reverse proxy. Demonstrates the `forwardAuth` middleware wired up to a
   sample `whoami` service. This is documentation — not a production-ready deployment by itself.

An **`.env.example`** file at the repo root documents every required and optional variable.

### Changes Required

#### 1. `docker-compose.yml`

**File**: `docker-compose.yml`

```yaml
# docker-compose.yml — Standalone Passage deployment
#
# Usage:
#   1. cp .env.example .env
#   2. Edit .env with your values
#   3. docker compose up -d
#
# Passage will listen on port 8080 by default. Put it behind your
# existing reverse proxy (Nginx, Traefik, Caddy) for TLS termination.

services:
  passage:
    image: ghcr.io/crueber/passage:latest
    # Uncomment to build from source instead:
    # build: .
    restart: unless-stopped
    ports:
      - "${PASSAGE_PORT:-8080}:8080"
    environment:
      # Server
      PASSAGE_SERVER_BASE_URL: "${PASSAGE_SERVER_BASE_URL}"
      PASSAGE_SERVER_HOST: "0.0.0.0"
      PASSAGE_SERVER_PORT: "8080"
      # Database — always points into the named volume
      PASSAGE_DATABASE_PATH: "/data/passage.db"
      # Session
      PASSAGE_SESSION_DURATION_HOURS: "${PASSAGE_SESSION_DURATION_HOURS:-24}"
      PASSAGE_SESSION_COOKIE_NAME: "${PASSAGE_SESSION_COOKIE_NAME:-passage_session}"
      PASSAGE_SESSION_COOKIE_SECURE: "${PASSAGE_SESSION_COOKIE_SECURE:-true}"
      # SMTP (optional — omit host to disable email features)
      PASSAGE_SMTP_HOST: "${PASSAGE_SMTP_HOST:-}"
      PASSAGE_SMTP_PORT: "${PASSAGE_SMTP_PORT:-587}"
      PASSAGE_SMTP_USERNAME: "${PASSAGE_SMTP_USERNAME:-}"
      PASSAGE_SMTP_PASSWORD: "${PASSAGE_SMTP_PASSWORD:-}"
      PASSAGE_SMTP_FROM: "${PASSAGE_SMTP_FROM:-}"
      PASSAGE_SMTP_TLS: "${PASSAGE_SMTP_TLS:-starttls}"
      # Auth
      PASSAGE_AUTH_ALLOW_REGISTRATION: "${PASSAGE_AUTH_ALLOW_REGISTRATION:-true}"
      PASSAGE_AUTH_BCRYPT_COST: "${PASSAGE_AUTH_BCRYPT_COST:-12}"
      # Logging
      PASSAGE_LOG_LEVEL: "${PASSAGE_LOG_LEVEL:-info}"
      PASSAGE_LOG_FORMAT: "${PASSAGE_LOG_FORMAT:-json}"
    volumes:
      - passage_data:/data
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 5s
      start_period: 15s
      retries: 3

volumes:
  passage_data:
    driver: local
```

#### 2. `.env.example`

**File**: `.env.example`

```dotenv
# .env.example — copy to .env and fill in your values.
# Lines starting with # are comments. Values without quotes are fine for
# most variables; quote values that contain spaces or special characters.

# ── Required ──────────────────────────────────────────────────────────────

# The public base URL Passage is reachable at (used for WebAuthn and redirects).
# Must match the URL your reverse proxy exposes to clients.
PASSAGE_SERVER_BASE_URL=https://auth.home.example.com

# ── Optional — Server ─────────────────────────────────────────────────────

# Host port to bind Passage on the Docker host (default: 8080)
PASSAGE_PORT=8080

# ── Optional — Session ────────────────────────────────────────────────────

PASSAGE_SESSION_DURATION_HOURS=24
PASSAGE_SESSION_COOKIE_NAME=passage_session
# Set to false only if running on http:// (local dev or HTTP-only home lab)
PASSAGE_SESSION_COOKIE_SECURE=true

# ── Optional — SMTP ───────────────────────────────────────────────────────
# Leave PASSAGE_SMTP_HOST empty to disable all email features (password reset).

PASSAGE_SMTP_HOST=smtp.example.com
PASSAGE_SMTP_PORT=587
PASSAGE_SMTP_USERNAME=passage@example.com
PASSAGE_SMTP_PASSWORD=changeme
PASSAGE_SMTP_FROM=Passage <passage@example.com>
# Allowed values: tls | starttls | none
PASSAGE_SMTP_TLS=starttls

# ── Optional — Auth ───────────────────────────────────────────────────────

# Allow new users to self-register (disable after initial setup)
PASSAGE_AUTH_ALLOW_REGISTRATION=true
# bcrypt cost — increase for higher security at the cost of slower logins (10–31)
PASSAGE_AUTH_BCRYPT_COST=12

# ── Optional — Logging ────────────────────────────────────────────────────

# Level: debug | info | warn | error
PASSAGE_LOG_LEVEL=info
# Format: json | text
PASSAGE_LOG_FORMAT=json
```

#### 3. `docs/traefik-compose-example.yml`

**File**: `docs/traefik-compose-example.yml`

```yaml
# docs/traefik-compose-example.yml
#
# EXAMPLE ONLY — not a production-ready deployment.
#
# This file shows how to integrate Passage with Traefik v3 as the reverse
# proxy on a home-lab host. It runs:
#   - Traefik (reverse proxy + TLS via ACME/Let's Encrypt)
#   - Passage (forward-auth provider)
#   - whoami (sample protected app)
#
# Prerequisites:
#   - A domain pointing at this host (e.g. home.example.com)
#   - Ports 80 and 443 open on the host
#
# Usage:
#   cp .env.example .env && nano .env
#   docker compose -f docs/traefik-compose-example.yml up -d

services:

  traefik:
    image: traefik:v3.3
    restart: unless-stopped
    command:
      - "--api.insecure=false"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      - "--certificatesresolvers.le.acme.httpchallenge=true"
      - "--certificatesresolvers.le.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.le.acme.email=${ACME_EMAIL}"
      - "--certificatesresolvers.le.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt

  passage:
    image: ghcr.io/crueber/passage:latest
    restart: unless-stopped
    environment:
      PASSAGE_SERVER_BASE_URL: "https://auth.${DOMAIN}"
      PASSAGE_DATABASE_PATH: "/data/passage.db"
      PASSAGE_SMTP_HOST: "${PASSAGE_SMTP_HOST:-}"
      PASSAGE_SMTP_PORT: "${PASSAGE_SMTP_PORT:-587}"
      PASSAGE_SMTP_USERNAME: "${PASSAGE_SMTP_USERNAME:-}"
      PASSAGE_SMTP_PASSWORD: "${PASSAGE_SMTP_PASSWORD:-}"
      PASSAGE_SMTP_FROM: "${PASSAGE_SMTP_FROM:-}"
      PASSAGE_SMTP_TLS: "${PASSAGE_SMTP_TLS:-starttls}"
      PASSAGE_SESSION_COOKIE_SECURE: "true"
      PASSAGE_LOG_FORMAT: "json"
    volumes:
      - passage_data:/data
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 5s
      start_period: 15s
      retries: 3
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.passage.rule=Host(`auth.${DOMAIN}`)"
      - "traefik.http.routers.passage.entrypoints=websecure"
      - "traefik.http.routers.passage.tls.certresolver=le"
      - "traefik.http.services.passage.loadbalancer.server.port=8080"
      # Define the forwardAuth middleware pointing at Passage's /auth/traefik endpoint.
      - "traefik.http.middlewares.passage-auth.forwardauth.address=http://passage:8080/auth/traefik"
      - "traefik.http.middlewares.passage-auth.forwardauth.authResponseHeaders=X-Passage-Username,X-Passage-Email,X-Passage-Name,X-Passage-User-ID,X-Passage-Is-Admin"
      - "traefik.http.middlewares.passage-auth.forwardauth.trustForwardHeader=true"

  # Sample protected app — replace with your actual services.
  whoami:
    image: traefik/whoami:latest
    restart: unless-stopped
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.whoami.rule=Host(`whoami.${DOMAIN}`)"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls.certresolver=le"
      - "traefik.http.routers.whoami.middlewares=passage-auth"
      - "traefik.http.services.whoami.loadbalancer.server.port=80"

volumes:
  letsencrypt:
  passage_data:
    driver: local
```

### Success Criteria

#### Automated Verification
- [ ] `docker compose config` validates the Compose file without errors:
  ```bash
  docker compose config --quiet
  ```
- [ ] `docker compose up -d` starts successfully with a valid `.env` (copy from `.env.example`
      and set `PASSAGE_SERVER_BASE_URL=http://localhost:8080`)
- [ ] Container reaches healthy state: `docker compose ps` shows `healthy`
- [ ] `/healthz` responds: `curl -sf http://localhost:8080/healthz | jq .status` returns `"ok"`
- [ ] Login page is reachable: `curl -sf -o /dev/null -w "%{http_code}" http://localhost:8080/login` returns `200`
- [ ] Data persists across restarts:
  ```bash
  docker compose restart passage
  sleep 5
  curl -sf http://localhost:8080/healthz
  ```
- [ ] Named volume is created and survives `docker compose down` (without `-v`):
  ```bash
  docker compose down
  docker volume ls | grep passage_data
  ```
- [ ] `.env.example` is committed but `.env` is in `.gitignore` (already is — verify with `git status`)

#### Manual Verification
- [ ] Register a user at `http://localhost:8080/register` and confirm login works end-to-end
- [ ] After `docker compose down && docker compose up -d`, confirm the registered user can still
      log in (data survived the restart via the named volume)
- [ ] Confirm the Traefik example YAML renders without syntax errors in an editor or YAML linter:
      `docker run --rm -v $(pwd)/docs:/docs cytopia/yamllint:latest /docs/traefik-compose-example.yml`

**Implementation Note**: After Phase 3 passes all automated checks and at least the first two
manual steps pass (register, persist across restart), the deployment plan is complete.

---

## Testing Strategy

### Dockerfile (Phase 1)
- Build the image locally and verify size, user, and health check response.
- Run the official `docker scout` or `trivy` scan against the image to catch known CVEs:
  ```bash
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy:latest image passage:local
  ```

### GitHub Actions (Phase 2)
- Open a pull request with the workflow file and verify the `test` job runs but `publish` does not.
- Merge to `main` and verify `publish` runs and the image appears on GHCR.
- Push a test tag (`v0.1.0-test`) and verify semver tags are created, then delete the tag and image.

### Docker Compose (Phase 3)
- Run the standalone Compose file locally before committing.
- Validate the Traefik example with `yamllint` and a Traefik config validator if available.

---

## Security Hardening Notes

These are not blockers for the initial deployment but are worth tracking:

| Item | Notes |
|---|---|
| Run as non-root | Implemented — user `passage` (uid 1000) in the Dockerfile |
| Read-only root filesystem | Optional enhancement: add `read_only: true` to the Compose service and add `tmpfs: ["/tmp"]`; this requires ensuring no writes happen outside `/data` |
| No `--privileged` | Never needed for Passage |
| SMTP credentials | Passed via env var from `.env` — not baked into the image |
| SQLite in a named volume | The `/data` volume is never part of the image layers |
| Image signing | Optional: add `cosign` signing step to the workflow after initial deployment is stable |

---

## Migration Notes

This is a new deployment artifact — no data migrations are required. The SQLite schema migrations
run automatically at startup via goose (already implemented in Phase 1 of the original plan).

**First-boot checklist for self-hosters:**
1. Copy `.env.example` to `.env` and set at minimum `PASSAGE_SERVER_BASE_URL`.
2. `docker compose up -d`
3. Navigate to `http://<host>:8080/register` to create the first admin user.
4. Log in to `/admin` and disable `auth.allow_registration` if you don't want open registration.

---

## References

- Original implementation plan: `plans/2026-03-23-passage-auth-proxy.md`
- Config env var mapping: `internal/config/config.go:150-237`
- Version variable: `cmd/passage/run.go:35`
- Health check endpoint: `cmd/passage/run.go:170-177`
- Existing Traefik example: `docs/traefik-example.yaml`
- Existing Nginx example: `docs/nginx-example.conf`
- GHCR documentation: https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry
- `docker/metadata-action` tag patterns: https://github.com/docker/metadata-action#tags-input
