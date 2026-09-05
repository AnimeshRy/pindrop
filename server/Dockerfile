# Builds the Pindrop product API (server/), a separate Go module from the root
# CLI: this is the hosted service talking to Postgres and Supabase Auth, no
# scanner dependencies. Build context is server/, not the repo root.
#
#   docker build -t pindrop-server server/
#
# Migrations are embedded (internal/syncstore/postgres/migrations) and applied
# automatically by postgres.Open on startup — nothing extra to run here.

ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/server ./cmd/server

# distroless rather than alpine: the binary is CGO_ENABLED=0, so it needs no
# libc, and this image already ships ca-certificates (required to verify
# Supabase's TLS) plus a nonroot user — no shell or package manager on a
# service that's part of a security product.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=build /out/server /usr/local/bin/pindrop-server

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pindrop-server"]
