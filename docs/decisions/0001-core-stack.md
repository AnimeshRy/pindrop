# 0001 — Core stack

**Status:** Accepted
**Date:** 2026-08-02

## Context

Greenfield security product. The author is learning Go while building it, which
argues for boring, well-documented choices over clever ones.

## Decision

### Go

Beyond the usual single-binary and concurrency arguments, one reason is specific
to this domain: **Trivy, Gitleaks, Grype, Syft, and Kubescape are all written in
Go and all Apache-2.0 or MIT.** Even though we invoke them as subprocesses
today ([ADR 0002](0002-trivy-subprocess.md)), the option to import the small
ones remains open in a way it would not from Python or Node.

Target **Go 1.26**, with `toolchain go1.26.5` in `go.mod`. Go supports the two
most recent majors; 1.24 and below are end-of-life.

### cobra for the CLI

v1.10.2, stable, no v2 on the horizon. `urfave/cli` v3 is actively developed but
broke its API from v2 (explicit `context.Context`, `App` collapsed into
`Command`, generic flags). For a multi-command CLI with subcommands and
completion, cobra is the boring correct answer.

### stdlib net/http now, Gin later

Go 1.22 added method-qualified `ServeMux` patterns (`"GET /api/v1/findings"`,
`r.PathValue`). Phase 0 serves static files and three handlers; a framework
would be pure dependency for no benefit. Gin arrives in Phase 3 with a real API
surface, orgs, and middleware needs.

### sqlc over an ORM (Phase 3)

The workload is hash-based dedup upserts at scale, JSONB metadata columns, and
heavy filtered aggregations for rollups. ORMs are weakest at exactly that — you
end up writing raw SQL anyway and lose type safety doing it. `sqlc` generates
type-safe Go from SQL at build time, which inverts the trade.

Pairs with `pgx/v5` and `goose` for migrations. **Never run auto-migrate against
a production security database.**

If an ORM ever becomes necessary, `Ent` is the better Go choice than GORM.

### River for background jobs (Phase 3)

Postgres-native, built on `SELECT ... FOR UPDATE SKIP LOCKED` — the same
primitive a hand-rolled worker would use, but with retries, backoff, scheduling,
and a UI already solved. It removes the need for Redis entirely.

Caveat: River is **pre-1.0** (v0.42.0) with no API stability guarantee. Pin
exactly and read release notes on every bump.

### Connect-RPC over raw gRPC (Phase 3+)

Raw gRPC cannot be called from a browser without a grpc-web proxy. Connect
speaks gRPC, gRPC-Web, and plain HTTP/JSON from one handler, so a single
protobuf schema serves the dashboard, the CLI, and future remote scanning
agents, with generated TypeScript clients and no Envoy.

gRPC's genuinely strong use case here is the **agent protocol** — remote runners
scanning inside a customer's VPC over mTLS, streaming findings back.

## Consequences

- Single distributable binary; `docker run` or `./pindrop` and it works.
- Boring, well-documented dependencies suit someone learning the language.
- SQL is written by hand, which is more upfront typing and far better at the
  query shapes this product needs.
- River being pre-1.0 means occasional breaking upgrades to absorb.

## Alternatives considered

| Rejected | Why |
|---|---|
| GORM | Poor fit for upsert-heavy, aggregation-heavy, JSONB workloads; risky auto-migration |
| Gin from day one | Framework overhead for a static file server plus three routes |
| urfave/cli v3 | Recent breaking API churn; cobra is steadier |
| asynq (Redis queue) | Adds Redis; River keeps the stack to Postgres alone |
| Raw gRPC for the dashboard | Needs a proxy for browsers; Connect removes the problem |
