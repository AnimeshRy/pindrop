# Development setup

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| **Go** | 1.26+ | `go.mod` declares `toolchain go1.26.5`; with the default `GOTOOLCHAIN=auto` an older Go auto-downloads it |
| **Node** | 22.13+ | Floor is set by pnpm 11, which is stricter than Vite 8's |
| **pnpm** | 11.x | `corepack enable pnpm` |
| **Trivy** | 0.72.0 | Scanner used by `pindrop scan`; `make setup` installs it |
| **OSV-Scanner** | 2.4.0 | Scanner; `make setup` installs it |
| **Opengrep** | 1.26.0 | Scanner; `make setup` installs it |
| **TruffleHog** | 3.96.0 | Scanner; `make setup` installs it. AGPL — subprocess only, never imported |

Every scanner is optional at runtime. A missing one is reported with install
guidance and dropped, so `pindrop scan .` works with any subset installed; only
an empty set is fatal.

## First run

```bash
make setup          # Go tools + scanners into ./bin, then pnpm install
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

`make setup` installs the pinned scanners into `./bin`. **`./bin` does not need to
be on your PATH** — pindrop looks for each tool on PATH first, then beside its own
executable. To use copies you already have, pass `--trivy-binary`, `--osv-binary`,
`--opengrep-binary`, or `--trufflehog-binary`.

Note that `mise.toml` covers Trivy but not OSV-Scanner, Opengrep, or TruffleHog,
so `make setup` installs those three into `./bin` even on a mise-managed machine.

Every scanner is pinned rather than tracking latest. Trivy's release channel was
compromised twice in 2026, and each tool's report schema is a contract we parse.
Opengrep has no install script we can pin, so the Makefile downloads the
single-file release asset for the current platform directly — the `opengrep_*`
asset, never `opengrep-core_*`, which is the internal engine alone.

Opengrep's first run of a given version is slow: the distributed binary is a
Nuitka `--onefile` build and self-extracts its embedded engine into the user cache
before doing any work.

## Make targets

```
make help          list everything
make setup         install Go tools, scanners, and frontend dependencies
make mise          install the optional mise-managed toolchain
make trivy         install just the pinned Trivy
make osv-scanner   install just the pinned OSV-Scanner
make opengrep      install just the pinned Opengrep
make trufflehog    install just the pinned TruffleHog
make build         frontend + binary (the full artifact)
make build-go      Go binary only, reusing whatever is in web/dist
make web           frontend only
make dev           Vite dev server, proxying /api to localhost:7777
make test          go test -race ./...
make lint          golangci-lint + eslint + tsc
make fmt           format Go and frontend
make check         lint + test
make run-scan      scan the bundled fixture
make run-scan-secrets
                   scan a throwaway credential dir — the secrets path,
                   which the fixture cannot exercise
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

Four behaviors worth checking by hand, because they are the ones users hit:

```bash
# A missing scanner must give guidance, not a raw exec error, and must not
# abort the scan while any other scanner is usable.
./bin/pindrop scan . --trivy-binary nope

# Fingerprints must be byte-identical across runs
./bin/pindrop scan ./testdata/vulnerable-app --format json --out /tmp/a.json
./bin/pindrop scan ./testdata/vulnerable-app --format json --out /tmp/b.json
diff <(jq -S '[.findings[].fingerprint]|sort' /tmp/a.json) \
     <(jq -S '[.findings[].fingerprint]|sort' /tmp/b.json)

# ...and across a reformat, which is the property triage depends on. Reindent a
# fixture source file, rescan, and the code findings' fingerprints must not move
# even though their line numbers do.
./bin/pindrop scan ./testdata/vulnerable-app --format json --out /tmp/c.json
diff <(jq -S '[.findings[]|select(.category=="code")|.fingerprint]|sort' /tmp/a.json) \
     <(jq -S '[.findings[]|select(.category=="code")|.fingerprint]|sort' /tmp/c.json)

# Opengrep's bundled rules must stay quiet on real code. Anything but 0 here
# means a rule is too broad.
./bin/pindrop scan ./internal --trivy-binary nope --osv-binary nope --format json \
  | jq '[.findings[]|select(.category=="code")]|length'

# The same gate for secrets, which the check above does not cover. Note this
# scans internal/, which holds TruffleHog's own golden fixture — the fixture's
# secret material is substituted precisely so this stays 0.
./bin/pindrop scan ./internal --trivy-binary nope --osv-binary nope \
  --opengrep-binary nope --format json \
  | jq '[.findings[]|select(.category=="secret")]|length'

# The secrets path, which the fixture cannot exercise — it contains no
# detectable credential by design. This generates five into a temp directory,
# scans it, and destroys it. Expect 8 findings from 5 credentials: three are
# reported by both Trivy and TruffleHog. See docs/architecture/scanners.md.
make run-scan-secrets

# And no plaintext may reach the report. CI asserts this; to check by hand,
# scan a throwaway dir and grep for the values you planted. Every hit is a bug.
```

CI runs all of this except the reformat check, which needs a working-tree edit.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `pattern all:dist: no matching files` | `web/dist/` missing — restore `.gitkeep` |
| golangci-lint rejects the config | v1 binary against a v2 config; use `./bin/golangci-lint` |
| `Dashboard not built` page | Binary compiled before `pnpm build`; run `make build` |
| `no scan report at .pindrop/report.json` | Not an error — run a scan with `--out` first |
| Slow first scan | Trivy downloading its vulnerability DB; pass `--cache-dir` to reuse it |
| Slow first Opengrep scan | Its `--onefile` binary self-extracting into the user cache; once per version |
| `trivy not found in PATH` | Run `make trivy`, or pass `--trivy-binary` |
| No `category: code` findings at all | Opengrep missing (check stderr for the skip warning), or `--opengrep-rules` pointing somewhere empty |
| Opengrep fails with exit 7 | A rule file failed to parse. Usually an unquoted YAML scalar containing `: ` — quote the pattern |
| No `category: secret` findings at all | Expected on this repository and on the bundled fixture, neither of which contains a detectable secret. Check TruffleHog is present (stderr shows a skip warning if not) |
| A secret shows as `high`, not `critical` | Verification is off by default, so nothing is proven live. Pass `--verify-secrets` — note it sends the credentials it finds to third-party APIs ([ADR 0008](../decisions/0008-trufflehog-verification-opt-in.md)) |
| `--fail-on high` newly fails after upgrading | Unverified secrets grade `high`, so a secret-shaped placeholder that previously went unreported now trips the threshold |
| `compile: version "goX" does not match go tool version "goY"` | An exported `GOROOT` — from your shell profile, or from mise if its `go` version differs from `go.mod`'s `toolchain`. Remove it / align the versions. The Makefile already clears it. |
