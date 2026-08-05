# Pindrop — context for Claude Code

## What this is

A security scanning product for small teams shipping AI-generated code.

**The thesis, which drives every design decision:** the scanners are commodity —
anyone can `brew install trivy`. The product is the **correlation layer** that
turns thousands of raw scanner events into eight ranked issues a non-expert can
act on. Normalization, stable identity, cross-tool dedup, durable triage state,
and prioritization.

If a change makes output noisier or identity less stable, it is working against
the product.

Full context: [docs/product/vision.md](docs/product/vision.md).

## Current state — Phase 0 complete

`pindrop scan` (Trivy, OSV-Scanner, and Opengrep) and `pindrop serve` (embedded
React dashboard).
**Nothing is persisted yet** — fingerprints are computed and displayed but not
compared across runs. Cross-scan diffing and triage are Phase 1.

Cross-tool identity and dedup (`scan.Dedup`, `canonical.go`,
[ADR 0006](docs/decisions/0006-canonical-identity-before-dedup.md)) landed early,
because they change fingerprints and must precede persistence. Adding OSV-Scanner
then cost nothing in noise: 14 raw findings on the fixture merge to the same 8
Trivy alone reported, four of them now corroborated by both tools.

Opengrep followed, adding source-code findings (`category: code`). It needed no
fingerprint change — `CategoryCode` already hashed rule ID, path, and normalized
snippet — but it did need a ruleset, because no redistributable one exists
([ADR 0007](docs/decisions/0007-first-party-opengrep-rules.md)). Its 11 fixture
findings are all net new, since a SAST finding has nothing to merge with; the
number to watch for this scanner is precision, and it reports 0 against the
project's own source.

Next: [docs/product/roadmap.md](docs/product/roadmap.md).

## Read before changing

| Area | Doc |
|---|---|
| Where code goes and why | [docs/architecture/repo-layout.md](docs/architecture/repo-layout.md) |
| Finding identity — **read before touching fingerprints** | [docs/architecture/finding-model.md](docs/architecture/finding-model.md) |
| Adding a scanner, and licensing traps | [docs/architecture/scanners.md](docs/architecture/scanners.md) |
| Why things are the way they are | [docs/decisions/](docs/decisions/) |
| Coding conventions | [docs/development/conventions.md](docs/development/conventions.md) |
| Build and verify | [docs/development/setup.md](docs/development/setup.md) |

## Commands

```bash
make build     # frontend + binary → ./bin/pindrop
make check     # lint + test, Go and frontend
make test      # go test -race ./...
make run-scan  # scan the bundled fixture
```

Never a golangci-lint from `PATH` — a system-wide v1 cannot read the v2 config.
Use `./bin/golangci-lint`, or `mise which golangci-lint` if the developer uses
mise; `make lint-go` already resolves whichever applies.

## Things that will bite you

**`internal/scan` must not import any adapter.** `trivy` imports `scan`; the
registry lives in `internal/cli`. Reversing that is an import cycle.

**Fingerprints exclude line numbers and scanner names, on purpose.** Adding
either would report every finding as fixed-and-reintroduced after any edit
above it, and would stop two tools' reports of one problem from merging.
Changing `scan.Fingerprint` orphans every stored triage decision — treat it as a
data migration.

**Excluding the scanner name is not enough to merge two tools.** They also
disagree on advisory IDs (`CVE-2025-22870` vs `GO-2025-3503`), ecosystem names
(`gomod` vs `Go`), and version strings (`v0.35.0` vs `0.35.0`). `canonical.go`
normalizes all three before hashing. **New adapters must populate
`Finding.Aliases`** — omitting it fails no test and silently stops merging.
Canonicalization must never depend on which scanners ran, or enabling one rewrites
existing findings' identity.

**Cloud and cluster findings have no file path.** A security group or IRSA role is
identified by resource ARN plus check ID, and keying on an ephemeral resource
would report everything as fixed-and-reintroduced on each node rotation. Resource
identity must be designed before Phase 1 persists anything.

**Golden fixtures come from real tool output, never from documentation.** The
Trivy adapter shipped reading an `AVDID` field that v0.72.0 does not emit,
because the fixture was written from docs. Capture, then trim.

**`--exit-code 0` on every Trivy invocation.** Without it, "the tool crashed"
and "the code has vulnerabilities" are the same exit code.

**A missing scanner binary must not fail the scan.** `scan.Usable` drops
unavailable scanners and the CLI warns; only an empty usable set is fatal.
Requiring every tool to be installed breaks the zero-setup first run. Relatedly,
not every tool has Trivy's `--exit-code 0`: OSV-Scanner signals findings *through*
its exit code, so `osv.resultExit` classifies them (0 and 1–126 fine, 128 means no
manifests, 127 and 129+ are failures).

**Opengrep has three flags that are not optional.** Omitting `--config` does not
mean "no rules" — it means `auto`, which downloads ~2.4 MB of Semgrep-licensed
rules from `semgrep.dev` on every scan. `--no-rewrite-rule-ids` stops Opengrep
prefixing each rule's id with its file path, which matters because `check_id`
becomes `Finding.RuleID` and is a fingerprint input; **renaming a bundled rule is
a data migration.** `--no-git-ignore` stops it scanning only git-tracked files,
which otherwise turns an untracked target into a silent, successful zero findings.
And never pass `--error`: findings exit 0 here, so non-zero unambiguously means
the tool broke. Rules are first-party by necessity — every existing corpus
forbids commercial use ([ADR
0007](docs/decisions/0007-first-party-opengrep-rules.md)).

**Adapters must filter, not just forward.** Trivy's license scanner classifies
every license it finds; forwarding all of them produced 24 MIT/Apache entries
against 8 real problems on this repo. `actionableLicense` keeps only copyleft
categories. After wiring any new scanner, scan a healthy repo — if the count
jumps by more than a handful, it needs a filter before it ships.

**TruffleHog is AGPL-3.0.** Subprocess only. Importing it would place this
entire codebase under AGPL.

**`web/dist/.gitkeep` must stay committed** or `//go:embed all:dist` fails to
compile on a fresh clone.

**golangci-lint needs `GOTOOLCHAIN=go1.26.5` at install time** — the published
build targets Go 1.25 and refuses a 1.26 module. The Makefile does this.

**`mise.toml` is optional and must stay that way** ([ADR
0005](docs/decisions/0005-mise-optional.md)). Every target works without mise,
and CI does not use it. Its `go` version must stay byte-identical to `go.mod`'s
`toolchain` directive — mise exports `GOROOT`, and a mismatch triggers the
toolchain re-exec bug below. A version bump means updating `mise.toml`, the
`Makefile`, and `ci.yml` together.

**Never invoke a bare `go` in the Makefile — use `$(GO)`.** It expands to
`$(NO_GOROOT) go`. An exported `GOROOT` (common in shell profiles) breaks every
build once `GOTOOLCHAIN` switches toolchains: the driver re-execs into the new
toolchain while `GOROOT` still points at the old install's stdlib.

This applies to **every Go-aware tool, not just the driver** — prefix
`$(NO_GOROOT)`. golangci-lint reads `GOROOT` too and fails identically, but
reports the mismatch against an unrelated import (`could not import errors`),
which sends you looking in the wrong place.

**TypeScript is pinned to 6.x deliberately**
([ADR 0004](docs/decisions/0004-typescript-6-pin.md)) — `typescript-eslint`
cannot run on TS 7. Do not "helpfully" upgrade it.

## Style, briefly

Go: `os.Exit` only in `main()`; the `run()` pattern; no `init()`; no
`util`/`common` packages; wrap errors with `%w` at the end; doc comments on all
exported symbols; table-driven parallel tests; prefer stdlib — every dependency
in a security tool is supply-chain surface.

**User-facing errors must be actionable.** Our users are not security engineers.
`"trivy not found in PATH"` plus an install URL, never a raw exec error.

TypeScript: no `any`; no constructor parameter properties (`erasableSyntaxOnly`);
wide content scrolls in its own container; severity is never conveyed by color
alone.

## When you finish something

Update the doc that your change invalidated, in the same change. A new
non-obvious decision gets a new ADR; reversing one gets a *new* ADR that
supersedes the old, never an edit.
