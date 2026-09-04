# Builds the Pindrop product API (server/). This is a separate Go module from
# the root CLI and a separate image — the CLI is a distributed binary users run
# locally, this is a service that talks to Postgres and Supabase Auth and has no
# scanner dependencies at all.
#
# The build context is server/, not the repo root. Cloud Run's console shows no
# build-context field, but it derives one from the Dockerfile path: the
# generated trigger runs `docker build ... server -f server/Dockerfile`. Do not
# "fix" these COPY paths to be repo-root-relative — that fails the deploy at
# `COPY server/go.mod`, and the trigger's own build step is the only place the
# context is visible.
#
# Build:                    docker build -t pindrop-server server/
# Run:                      docker run --rm -p 8080:8080 \
#                             -e SUPABASE_PROJECT_URL=... \
#                             -e DATABASE_URL=postgres://... \
#                             -e CORS_ORIGIN=https://app.example.com \
#                             pindrop-server
#
# go.work is deliberately NOT copied: the server module is self-contained, and
# the workspace file references ../ which does not exist inside the image.
#
# No `RUN --mount=type=cache` anywhere: that needs BuildKit, and the trigger
# Cloud Run generates runs the legacy docker builder, which fails outright with
# "the --mount option requires BuildKit". Layer caching there comes from the
# trigger's own --cache-from instead.
#
# Migrations are embedded (internal/syncstore/postgres/migrations) and applied
# automatically by postgres.Open on startup — nothing extra to run here.

ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Defaults, not bare ARGs: TARGETOS/TARGETARCH are supplied by BuildKit, and
# Cloud Run's console-generated trigger builds with the legacy docker builder,
# where they expand to empty strings. Empty happens to yield the host's
# linux/amd64 there, but silently — pinning the default makes the deployed
# architecture explicit while BuildKit still overrides it for cross-builds.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/server ./cmd/server

# distroless rather than alpine: the binary is CGO_ENABLED=0, so it needs no
# libc, and this image already ships ca-certificates (required to verify
# Supabase's TLS) plus a nonroot user. That removes the `apk add` step, which
# means the image builds on networks with a TLS-intercepting proxy, where
# fetching Alpine's package index fails with a certificate error. It also drops
# the shell and package manager from a service that is part of a security
# product.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=build /out/server /usr/local/bin/pindrop-server

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pindrop-server"]
