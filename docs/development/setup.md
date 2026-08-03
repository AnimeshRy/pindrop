# Development setup

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| **Go** | 1.26+ | `go.mod` declares `toolchain go1.26.5`; with the default `GOTOOLCHAIN=auto` an older Go auto-downloads it |
| **Node** | 22.13+ | Floor is set by pnpm 11, which is stricter than Vite 8's |
| **pnpm** | 11.x | `corepack enable pnpm` |
| **Trivy** | 0.72.0 | Runtime dependency of `pindrop scan`; `make setup` installs it |

## First run

```bash
make setup          # Go tools + Trivy into ./bin, then pnpm install
make build          # frontend build + Go binary → ./bin/pindrop
./bin/pindrop scan .
```

## Optional: mise

[`mise.toml`](../../mise.toml) declares every pinned version — Go, Node, pnpm,
Trivy, golangci-lint, gofumpt — in one place. It is **optional**
([ADR 0005](../decisions/0005-mise-optional.md)): the Makefile installs anything
mise has not provided, and CI does not use it.

```bash
mise trust && mise install    # or: make mise
make setup                    # now skips whatever mise provides
```

Three things to know:

- Make resolves tool paths at startup, so a fresh `mise install` is only picked
  up on the **next** `make` invocation.
- Targets resolve tools with `mise which`, never `command -v`, so a system-wide
  golangci-lint v1 on your PATH is ignored rather than used against our v2
  config.
- Keep `go` in `mise.toml` byte-identical to the `toolchain` directive in
  `go.mod`. mise exports `GOROOT`; if the two disagree the go driver re-execs
  into a different toolchain and hits the version-mismatch error below.

`make setup` installs a pinned Trivy into `./bin`. **`./bin` does not need to be
on your PATH** — pindrop looks for `trivy` on PATH first, then beside its own
executable. To use a copy you already have, pass `--trivy-binary /path/to/trivy`.

Trivy is pinned rather than tracking latest: its release channel was compromised
twice in 2026, and its report schema is a contract we parse.

## Make targets

```
make help          list everything
make setup         install Go tools, Trivy, and frontend dependencies
make mise          install the optional mise-managed toolchain
make trivy         install just the pinned Trivy
make build         frontend + binary (the full artifact)
make build-go      Go binary only, reusing whatever is in web/dist
make web           frontend only
make dev           Vite dev server, proxying /api to localhost:7777
make test          go test -race ./...
make lint          golangci-lint + eslint + tsc
make fmt           format Go and frontend
make check         lint + test
make run-scan      scan the bundled fixture
make run-serve     scan the fixture, then serve the dashboard
make clean         remove build artifacts
```

## Two toolchain gotchas

**golangci-lint must be built with Go 1.26.** The published binary is compiled
against Go 1.25 and refuses to analyze a module whose `go` directive is newer:

```
the Go language version (go1.25) used to build golangci-lint
is lower than the targeted Go version (1.26.5)
```

The Makefile handles this by forcing `GOTOOLCHAIN=go1.26.5` during install. If
you install it by hand, do the same. A system-wide golangci-lint v1 cannot read
this repository's v2 config at all — always use `./bin/golangci-lint`.

**`web/dist/.gitkeep` must stay committed.** `//go:embed all:dist` fails to
compile if the directory does not exist, so a fresh clone needs it before
anyone has run `pnpm build`.

## Frontend development loop

Two terminals:

```bash
# 1 — API + a report to serve
./bin/pindrop scan . --format json --out .pindrop/report.json
./bin/pindrop serve

# 2 — Vite with HMR, proxying /api to the above
make dev            # http://localhost:5173
```

The report is re-read on every request, so re-running a scan shows up on the
next refresh without restarting anything.

## Verifying a change end to end

```bash
go build ./... && go vet ./... && go test -race ./...
./bin/golangci-lint run ./...
pnpm --dir web typecheck && pnpm --dir web lint && pnpm --dir web build
make build

./bin/pindrop scan ./testdata/vulnerable-app
./bin/pindrop scan ./testdata/vulnerable-app --format json --out /tmp/r.json
./bin/pindrop scan ./testdata/vulnerable-app --format sarif | head -20

./bin/pindrop serve --results /tmp/r.json &
curl -s localhost:7777/api/v1/healthz
curl -s localhost:7777/api/v1/findings | head -40
curl -s -o /dev/null -w '%{http_code}\n' localhost:7777/deep/link   # 200, SPA shell
```

Two behaviors worth checking by hand, because they are the ones users hit:

```bash
# Missing Trivy must give guidance, not a raw exec error
./bin/pindrop scan . --trivy-binary nope

# Fingerprints must be byte-identical across runs
./bin/pindrop scan ./testdata/vulnerable-app --format json --out /tmp/a.json
./bin/pindrop scan ./testdata/vulnerable-app --format json --out /tmp/b.json
diff <(jq -S '[.findings[].fingerprint]|sort' /tmp/a.json) \
     <(jq -S '[.findings[].fingerprint]|sort' /tmp/b.json)
```

CI runs all of this, including the two above.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `pattern all:dist: no matching files` | `web/dist/` missing — restore `.gitkeep` |
| golangci-lint rejects the config | v1 binary against a v2 config; use `./bin/golangci-lint` |
| `Dashboard not built` page | Binary compiled before `pnpm build`; run `make build` |
| `no scan report at .pindrop/report.json` | Not an error — run a scan with `--out` first |
| Slow first scan | Trivy downloading its vulnerability DB; pass `--cache-dir` to reuse it |
| `trivy not found in PATH` | Run `make trivy`, or pass `--trivy-binary` |
| `compile: version "goX" does not match go tool version "goY"` | An exported `GOROOT` — from your shell profile, or from mise if its `go` version differs from `go.mod`'s `toolchain`. Remove it / align the versions. The Makefile already clears it. |
