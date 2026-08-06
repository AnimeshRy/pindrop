# Pindrop

Security scanning that tells you what to fix, not everything that's wrong.

Pindrop runs existing scanners over your code, normalizes their output into one
model, gives every finding a stable identity, and ranks the result — so you read
eight lines instead of two thousand.

```console
$ pindrop scan .
SEVERITY  CATEGORY          RULE            LOCATION           SUMMARY
HIGH      misconfiguration  DS-0002         Dockerfile         Image user should not be 'root'
HIGH      vulnerability     CVE-2024-21538  package-lock.json  cross-spawn: regular expression denial of service
HIGH      vulnerability     CVE-2026-4800   package-lock.json  lodash: arbitrary code execution
MEDIUM    vulnerability     CVE-2020-28500  package-lock.json  nodejs-lodash: ReDoS via toNumber, trim and trimEnd
LOW       misconfiguration  DS-0026         Dockerfile         No HEALTHCHECK defined

8 findings  4 high  3 medium  1 low
  trivy scanned . in 0.92s
```

> **Status: early.** Phase 0 — one scanner, no persistence, no accounts. See the
> [roadmap](docs/product/roadmap.md).

## Why

Free scanners are one `brew install` away, and small teams still don't run them.
Not because of cost — because pointing Trivy at a real codebase returns two
thousand findings, and nobody triages two thousand findings. The output isn't
actionable, so it gets ignored, so the tool gets uninstalled.

The scanners are commodity. The work nobody wants to do is the layer above them:
one model instead of four JSON shapes, identity that survives code moving
around, deduplication across tools, triage decisions that stick forever, and
ranking that cuts the list down to what matters.

That layer is the product. More in [docs/product/vision.md](docs/product/vision.md).

## Install

Requires [Trivy](https://trivy.dev/latest/getting-started/installation/) on your
PATH.

```bash
git clone https://github.com/AnimeshRy/pindrop
cd pindrop
make setup && make build
./bin/pindrop scan .
```

## Usage

```bash
pindrop scan .                              # ranked table
pindrop scan . --format json --out r.json   # machine-readable
pindrop scan . --format sarif               # GitHub code scanning, IDEs
pindrop scan . --min-severity high          # filter
pindrop scan . --fail-on critical           # non-zero exit for CI
pindrop scan . --limit 0                    # show everything

pindrop serve --results r.json              # dashboard at :7777
```

Everything ships as **one 7.4 MB binary** with the dashboard embedded. No
runtime, no separate frontend deploy.

## What it finds

Dependency CVEs, leaked secrets, infrastructure misconfiguration, and license
violations via **Trivy**; a second advisory corpus via **OSV-Scanner**; insecure
patterns in source code via **Opengrep**, running rules we write ourselves; and
credentials via **TruffleHog**, which can additionally prove a key is *live* —
opt-in with `--verify-secrets`, because doing so sends the secrets it finds to
third-party APIs. zizmor is next; see
[docs/architecture/scanners.md](docs/architecture/scanners.md).

Every scanner is optional. A missing one reduces coverage and prints how to
install it; it does not fail the scan.

## Stable fingerprints

The part that makes triage worth doing:

```
your-app/api/users.go:42   →  someone adds an import  →  users.go:43
same fingerprint, same issue, still marked as a false positive
```

Identity deliberately excludes line numbers and the reporting scanner. Insert a
line and nothing churns. Two tools reporting the same problem collapse into one
issue, and their agreement becomes a confidence signal.

[How it works](docs/architecture/finding-model.md).

## Development

```bash
make help      # all targets
make check     # lint + test
make dev       # frontend with HMR
```

[Setup guide](docs/development/setup.md) ·
[Conventions](docs/development/conventions.md) ·
[Architecture](docs/architecture/overview.md) ·
[Decisions](docs/decisions/)

## License

Not yet chosen. All rights reserved for now; this will be settled before the
first public release.
