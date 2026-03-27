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
    adduser -D -u 1000 -h /home/passage passage && \
    mkdir -p /data && chown passage:passage /data

# Declare a volume for the SQLite database so it is never stored in the
# writable container layer. Operators must mount a persistent volume here.
VOLUME ["/data"]

WORKDIR /home/passage

COPY --from=builder /out/passage /usr/local/bin/passage

# Health check via the /healthz endpoint.
# start_period gives Passage time to run migrations on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

EXPOSE 8080

# Default: no config file — configure entirely via PASSAGE_* env vars.
# Set PASSAGE_DATABASE_PATH to a path under /data, e.g. /data/passage.db.
ENTRYPOINT ["/usr/local/bin/passage"]
