# Pindrop

Security scanning that tells you what to fix, not everything that's wrong.

Pindrop runs existing scanners over your code, normalizes their output into one
model, gives every finding a stable identity, and ranks the result — so you read
eight lines instead of two thousand.

```console
$ pindrop scan .

  Scanning .

  ✔ trivy          8 findings   640ms
  ✔ osv            6 findings   1.2s
  ✔ opengrep      11 findings   2.1s
  ✔ trufflehog     0 findings   770ms

  4/4 scanners · 25 raw findings

SEVERITY  CATEGORY          RULE                      LOCATION           SUMMARY
HIGH      misconfiguration  DS-0002                   Dockerfile         Image user should not be 'root'
HIGH      vulnerability     CVE-2024-21538            package-lock.json  cross-spawn: regular expression denial of service
HIGH      vulnerability     CVE-2026-4800             package-lock.json  lodash: arbitrary code execution via untrusted input
HIGH      code              go-sql-query-from-sprin…  src/admin.go:22    A SQL statement is assembled with fmt.Sprintf.
MEDIUM    vulnerability     CVE-2020-28500            package-lock.json  nodejs-lodash: ReDoS via toNumber, trim and trimEnd
LOW       misconfiguration  DS-0026                   Dockerfile         No HEALTHCHECK defined

19 findings  14 high  4 medium  1 low
```

Four scanners reported 25 raw findings; you read 19, because two tools agreeing
on one problem is one issue. The live rows go to stderr, so the table on stdout
still pipes cleanly into `jq`.

> **Status: early.** Four scanners, no persistence, no accounts. Cross-scan
> diffing and triage are next.

## Why

Free scanners are one `brew install` away, and small teams still don't run them.
Not because of cost — because pointing Trivy at a real codebase returns two
thousand findings, and nobody triages two thousand findings. The output isn't
actionable, so it gets ignored, so the tool gets uninstalled.

The scanners are commodity. The work nobody wants to do is the layer above them:
one model instead of four JSON shapes, identity that survives code moving
around, deduplication across tools, triage decisions that stick forever, and
ranking that cuts the list down to what matters.

That layer is the product.

## Install

There are no prebuilt binaries yet, so Pindrop is built from source. Building the
CLI needs **Go 1.26+** and nothing else — Node and pnpm are only required if you
also want the dashboard.

```bash
git clone https://github.com/AnimeshRy/pindrop
cd pindrop

make build-go            # → ./bin/pindrop
./bin/pindrop setup      # downloads and verifies the four scanners
./bin/pindrop scan .
```

That is the whole install. You do not need `make setup` — that target is for
contributors and installs linters, formatters, and frontend dependencies.

### What `pindrop setup` does

It downloads a pinned release of Trivy, OSV-Scanner, Opengrep, and TruffleHog for
your platform into `~/.pindrop/bin`, checking each one against a SHA-256 digest
committed inside the binary. A download that does not match is deleted and never
made executable.

- **~215 MB**, once. It prints the sizes and the hosts and asks before fetching
  anything; `--yes` skips the prompt.
- **Idempotent.** A second run installs nothing and makes *no network requests*,
  so there is no separate offline mode.
- **Self-contained.** Nothing is written outside `~/.pindrop`, no package manager
  is involved, and no sudo is needed. Delete that directory to undo it.
- **`~/.pindrop/bin` does not need to be on your PATH** — pindrop finds these
  itself.

Set `PINDROP_HOME` to put it somewhere else, or `--dir` to install into a
directory you choose.

### Checking what you actually have

```bash
./bin/pindrop setup --check
```

```console
Pindrop installs scanners into ~/.pindrop/bin

  opengrep      v1.26.0   installed  ~/.pindrop/bin/opengrep (pindrop setup)
  osv-scanner   v2.4.0    installed  ~/.pindrop/bin/osv-scanner (pindrop setup)
  trivy         v0.72.0   installed  ~/.pindrop/bin/trivy (pindrop setup)
  trufflehog    v3.96.0   installed  /opt/homebrew/bin/trufflehog (PATH)

4 of 4 scanners are ready to run.
```

The last column is the useful one. Pindrop looks for each tool on **PATH first**,
then beside its own binary, then in `~/.pindrop/bin` — so a copy you installed
yourself always wins, and `--check` tells you which one is really being used. It
also runs each tool, so it catches a binary that is present but broken or too old.

### Using scanners you already have

Skip `pindrop setup` entirely and point at them:

```bash
./bin/pindrop scan . --trivy-binary /usr/local/bin/trivy
```

Every scanner is optional. A missing one reduces coverage and prints how to
install it; only an empty set is fatal.

### Platforms

macOS and Linux, on x86-64 and arm64, including musl (Alpine). Windows is not
supported — Opengrep publishes no build for it.

### With the dashboard

The web UI is embedded in the binary, so it needs the frontend built first.
Additionally requires **Node 22.13+** and **pnpm 11**:

```bash
make setup && make build     # installs frontend deps, then builds everything
./bin/pindrop scan . --format json --out .pindrop/report.json
./bin/pindrop serve          # http://127.0.0.1:7777
```

A CLI-only build still runs `serve`, but it warns and serves the API alone.

## Run

```bash
pindrop scan .                              # ranked table
pindrop scan ~/code/some-repo               # any directory
```

On a terminal you get a live row per scanner while they run, and — if any are
missing — an offer to install them before the scan starts. In CI nothing prompts
and nothing animates.

```bash
pindrop scan . --format json --out r.json   # machine-readable
pindrop scan . --format sarif               # GitHub code scanning, IDEs
pindrop scan . --min-severity high          # filter
pindrop scan . --fail-on critical           # non-zero exit for CI
pindrop scan . --limit 0                    # show everything
pindrop scan . --verify-secrets             # prove a leaked key is live (see below)

pindrop setup --check                       # what is installed, and from where
pindrop setup --force                       # reinstall at the pinned versions
pindrop serve --results r.json              # dashboard at :7777
```

The progress display writes to **stderr** and the report to **stdout**, so
piping always works:

```bash
pindrop scan . --format json | jq '.findings[] | select(.severity == "critical")'
```

Override it with `--progress plain` (one line per scanner), `--progress none`, or
`--no-install` to never be prompted.

### In CI

Nothing extra is needed — no TTY means no prompts, no animation, and plain
output.

```bash
pindrop setup --yes
pindrop scan . --format sarif --out results.sarif --fail-on high
```

Cache `~/.pindrop/bin` between runs to avoid re-downloading the scanners.

Everything ships as **one binary** with the dashboard embedded. No runtime, no
separate frontend deploy.

## What it finds

Dependency CVEs, leaked secrets, infrastructure misconfiguration, and license
violations via **Trivy**; a second advisory corpus via **OSV-Scanner**; insecure
patterns in source code via **Opengrep**, running rules we write ourselves; and
credentials via **TruffleHog**, which can additionally prove a key is *live* —
opt-in with `--verify-secrets`, because doing so sends the secrets it finds to
third-party APIs. zizmor is next.

Two tools reporting the same problem collapse into one issue, and their agreement
becomes a confidence signal — which is why the fixture's 25 raw findings are shown
as 19.

## Stable fingerprints

The part that makes triage worth doing:

```
your-app/api/users.go:42   →  someone adds an import  →  users.go:43
same fingerprint, same issue, still marked as a false positive
```

Identity deliberately excludes line numbers and the reporting scanner. Insert a
line and nothing churns. Two tools reporting the same problem collapse into one
issue, and their agreement becomes a confidence signal.

## Development

```bash
make setup     # linters, formatters, frontend deps, scanners into ./bin
make build     # frontend + binary
make check     # lint + test
make dev       # frontend with HMR
make manifest  # regenerate the pinned scanner digests after a version bump
make help      # everything else
```

`make setup` is the contributor path and installs the scanners into `./bin`;
`pindrop setup` is the user path and installs them into `~/.pindrop/bin`. Both
work — `./bin` wins for a `./bin/pindrop`, because the sibling lookup is searched
before the managed directory.

Design docs (architecture, ADRs, setup details) live in a private repository
and are checked out as the `docs/` git submodule when you have access:

```bash
git clone --recurse-submodules git@github.com:AnimeshRy/pindrop.git
# or: git submodule update --init docs
```

## License

[Apache-2.0](LICENSE).

The scanners Pindrop runs are separately licensed and run as subprocesses, never
imported. `NOTICE` lists them.
