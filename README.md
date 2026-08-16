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

> **Status: early.** Four scanners, local scan history in SQLite, no accounts.
> Triage (`pindrop ignore`) and `pindrop scan --diff` are next.

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

### Homebrew (macOS / Linux)

```bash
brew tap AnimeshRy/pindrop https://github.com/AnimeshRy/pindrop
brew install pindrop
```

Or in one step (Homebrew resolves the tap URL when it can):

```bash
brew install AnimeshRy/pindrop/pindrop
```

Then download the scanners and scan:

```bash
pindrop setup
pindrop scan .
```

### Pre-built binaries

Download the latest release for your platform from
[GitHub Releases](https://github.com/AnimeshRy/pindrop/releases/latest),
extract it, and run `pindrop setup` before your first scan.

### From source

Requires Go 1.26+. Node and pnpm are only needed if you also want the
dashboard (`make build` rather than `make build-go`).

```bash
git clone https://github.com/AnimeshRy/pindrop
cd pindrop

make build-go            # → ./bin/pindrop
./bin/pindrop setup      # downloads and verifies the four scanners
./bin/pindrop scan .
```

You do not need `make setup` — that target is for contributors and installs
linters, formatters, and frontend dependencies.

### What `pindrop setup` does

It downloads a pinned release of Trivy, OSV-Scanner, Opengrep, and TruffleHog for
your platform into `~/.pindrop/bin`, checking each one against a SHA-256 digest
committed inside the binary. A download that does not match is deleted and never
made executable.

- **~215 MB**, once. It prints the sizes and the hosts and asks before fetching
  anything; `--yes` skips the prompt. On a terminal the confirmation is an
  interactive form rather than a bare `[Y/n]` line.
- **First run on a terminal** asks where to store data (`~/.pindrop` by default)
  and which scanners to install, using the same interactive UI. A custom data
  directory is saved in `~/.config/pindrop/config.json` (or the platform config
  dir) and used on every later run unless `PINDROP_HOME` is set.
- **Idempotent.** A second run installs nothing and makes *no network requests*,
  so there is no separate offline mode.
- **Self-contained.** Nothing is written outside `~/.pindrop`, no package manager
  is involved, and no sudo is needed. Delete that directory to undo it.
- **`~/.pindrop/bin` does not need to be on your PATH** — pindrop finds these
  itself.

Set `PINDROP_HOME` to put it somewhere else, or `--dir` to install into a
directory you choose.

### Removing what setup installed

```bash
./bin/pindrop uninstall              # remove scanners Pindrop installed; keeps scan history
./bin/pindrop uninstall --yes        # no confirmation for scanner removal
./bin/pindrop uninstall --purge-history   # also delete ~/.pindrop/pindrop.db
```

The `pindrop` binary itself is not removed — the command prints its path so you
can delete it manually.

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
./bin/pindrop scan .
./bin/pindrop serve          # http://127.0.0.1:7777 — browse recorded scan history
```

Use `make build`, not `make build-go`, when the dashboard has changed — the UI
is embedded from `web/dist/`, and a stale build produces blank repo pages even
when the API has data.

To serve a single JSON report file with no history instead:

```bash
./bin/pindrop scan . --format json --out .pindrop/report.json
./bin/pindrop serve --results .pindrop/report.json
```

A CLI-only build still runs `serve`, but it warns and serves the API alone.

## Run

```bash
pindrop scan .                              # ranked table
pindrop scan ~/code/some-repo               # any directory
```

On a terminal you get a live row per scanner while they run, and — if any are
missing — an offer to install them before the scan starts (same interactive
confirm as `pindrop setup`). In CI nothing prompts and nothing animates.

```bash
pindrop scan . --format json --out r.json   # machine-readable
pindrop scan . --format sarif               # GitHub code scanning, IDEs
pindrop scan . --min-severity high          # filter
pindrop scan . --fail-on critical           # non-zero exit for CI
pindrop scan . --limit 0                    # show everything
pindrop scan . --verify-secrets             # prove a leaked key is live (see below)

pindrop setup --check                       # what is installed, and from where
pindrop setup --force                       # reinstall at the pinned versions

pindrop completion bash                     # shell completions (see below)
pindrop update                              # check GitHub for a newer release
```

### Shell completions

Cobra generates these; output goes to **stdout** so you can redirect or `source` it:

```bash
source <(pindrop completion bash)           # bash
pindrop completion zsh > "${fpath[1]}/_pindrop"   # zsh (then compinit)
pindrop completion fish > ~/.config/fish/completions/pindrop.fish
```

Enum flags such as `--format`, `--min-severity`, and `--progress` complete to
their valid values.

### Updating pindrop

```bash
pindrop update                              # check GitHub, confirm, replace binary
pindrop update --yes                        # skip confirmation
```

This queries the latest release from GitHub and atomically replaces the running
executable. It is **non-functional until GoReleaser publishes a first release**
— dev builds (`version=dev`) are rejected, and a hash build with no release yet
reports already up to date or a network error. Checksum verification on the
downloaded archive is not wired yet; treat `pindrop update` as CLI surface for
now, not as strong an integrity guarantee as `pindrop setup`.

### History — did the fix actually land?

Every scan is recorded in `~/.pindrop/pindrop.db` (SQLite), so the next one can
tell you what changed rather than making you diff two JSON files by hand.

```bash
pindrop scan .                              # recorded automatically
pindrop scan . --no-history                 # don't record this one

pindrop status .                            # what is open right now
pindrop history                             # every repository ever scanned
pindrop history .                           # this repository's runs
pindrop serve                               # browse all of it at :7777
```

```
$ pindrop history .
WHEN      BRANCH  COMMIT   FINDINGS  CHANGED
just now  main    e90ddeb  18        no change
1m ago    main    e90ddeb  18        -1 no longer detected
1m ago    main    e90ddeb  19        first run
```

It says **"no longer detected"** rather than "fixed" on purpose. A scanner
ceasing to report something is a weaker claim than a fix, and three things can
make a finding disappear without anyone fixing it: a scanner that did not run,
an exclusion that was added, or a narrower directory being scanned. Pindrop
detects all three and declines to draw the conclusion rather than telling you
something was fixed when it was not.

```bash
pindrop history rm .                        # delete a repository's history
pindrop history prune --keep 20             # drop old runs
pindrop serve --results r.json              # single report file, no history
```

### Excluding noise

`node_modules`, virtualenvs, build output and vendored dependencies are skipped
by default, across all four scanners. On this repository that is the difference
between 43 findings and 24.

```bash
pindrop scan . --exclude third_party --exclude 'file:*.generated.go'
pindrop scan . --no-default-excludes
```

Or commit a `.pindrop.json` next to the code:

```json
{
  "exclude": {
    "dirs": ["third_party"],
    "files": ["*.generated.go"]
  }
}
```

Config entries add to the built-in set rather than replacing it, so you cannot
accidentally lose `.git` — whose exclusion is load-bearing, not cosmetic. Note
that `.env` files, `*.tfstate` and test directories are deliberately **not**
excluded: they are among the most common places a real credential is committed,
and skipping them would make secret scanning worse than `git grep`.

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

Identity deliberately excludes line numbers, the reporting scanner, and the
installed dependency version. Insert a line and nothing churns. Two tools
reporting the same problem collapse into one issue, and their agreement becomes
a confidence signal.

The version exclusion is the least obvious and matters most for dependencies:

```
golang.org/x/net v0.35.0  →  bump to v0.35.1  →  advisory is fixed in v0.36.0
same fingerprint, still one open issue — not "one resolved, one new"
```

A partial upgrade is the most common way a dependency finding changes. Keying
identity on the version would report it as a fix that never happened, and orphan
any triage decision attached to it.

## Development

```bash
make setup     # linters, formatters, frontend deps, scanners into ./bin
make build     # frontend + binary (run this when web/ changed)
make build-go  # Go binary only, reusing whatever is in web/dist
make check     # lint + test
make dev       # frontend with HMR
make sqlc      # regenerate history store queries after editing SQL
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
