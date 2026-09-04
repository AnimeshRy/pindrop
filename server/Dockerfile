# syntax=docker/dockerfile:1

# Builds the Pindrop product API (server/). This is a separate Go module from
# the root CLI and a separate image — the CLI is a distributed binary users run
# locally, this is a service that talks to Postgres and Supabase Auth and has no
# scanner dependencies at all.
#
# The build context is the REPO ROOT, not server/, so every COPY is prefixed
# with server/. Cloud Run's console-driven continuous deploy offers no build
# context setting and always hands Cloud Build the repository root, so a
# Dockerfile expecting server/ as its context cannot be deployed from the UI at
# all. Paths are prefixed here rather than in a second Dockerfile so there is
# one build to keep correct.
#
# Build:                    docker build -f server/Dockerfile -t pindrop-server .
# Run:                      docker run --rm -p 8080:8080 \
#                             -e SUPABASE_PROJECT_URL=... \
#                             -e DATABASE_URL=postgres://... \
#                             -e CORS_ORIGIN=https://app.example.com \
#                             pindrop-server
#
# go.work is deliberately NOT copied: the server module is self-contained, and
# the workspace file references ../ which does not exist inside the image.
#
# Migrations are embedded (internal/syncstore/postgres/migrations) and applied
# automatically by postgres.Open on startup — nothing extra to run here.

ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY server/ .
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/server ./cmd/server

FROM alpine:3.22 AS runtime
RUN apk add --no-cache ca-certificates \
    && addgroup -g 1001 -S pindrop \
    && adduser -S pindrop -u 1001 -G pindrop

COPY --from=build /out/server /usr/local/bin/pindrop-server

USER pindrop
EXPOSE 8080
ENTRYPOINT ["pindrop-server"]
