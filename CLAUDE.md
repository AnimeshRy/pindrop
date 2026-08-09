# Pindrop — context for Claude Code

Design docs live in the private [pindrop-docs](https://github.com/AnimeshRy/pindrop-docs)
submodule at `docs/`. After cloning, run `git submodule update --init docs`.

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

`pindrop scan` (Trivy, OSV-Scanner, Opengrep, and TruffleHog) and `pindrop serve`
(embedded React dashboard).
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

TruffleHog followed, unblocking the ADR the roadmap had been waiting on:
verification is **off by default** and opt-in via `--verify-secrets`
([ADR 0008](docs/decisions/0008-trufflehog-verification-opt-in.md)). It adds 0
findings on the fixture, which has no detectable secret by design, and 0 against
the project's own source. Two things about it are worth carrying forward: with
verification off it overlaps Trivy's 106 built-in secret rules and *will* report
shared credentials twice, structurally rather than incidentally; and it is the
first adapter whose snippet is derived rather than copied from the tool.

`pindrop setup` followed, which is what makes the CLI installable rather than
buildable: it downloads a pinned, digest-verified release of each scanner into
`~/.pindrop/bin` and needs no package manager
([ADR 0010](docs/decisions/0010-managed-scanner-installation.md)). Two things it
surfaced are worth carrying forward. Binary resolution gained a fourth location
and moved into `internal/toolpath`, out of the four adapters that had each copied
it. And running a scan in a stripped environment exposed a latent Opengrep bug
that had been silently discarding every code finding whenever no UTF-8 locale was
set — see below.

A live display followed, which is what makes a multi-minute scan legible: four
rows updating on stderr while the fan-out runs, degrading to plain lines the
moment stderr is not a terminal ([ADR
0011](docs/decisions/0011-bubbletea-for-progress.md)). It needed a rendering-free
seam in the domain — `scan.Observer` — and it is why the module now has 33
dependencies rather than 3. On a terminal, `pindrop scan` also offers to install
what is missing rather than only explaining it; in CI nothing prompts and the
behavior is byte-identical to before.

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
make manifest  # regenerate the pinned scanner digests after a version bump
make run-scan  # scan the bundled fixture
make run-scan-secrets  # scan a throwaway credential dir (the fixture has no secret)
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
entire codebase under AGPL. This is also why the Makefile installs it from a
pinned release rather than with `go install` as it does for OSV-Scanner — keeping
it out of the module graph means nobody can move it into a tools file later.

**TruffleHog has four non-obvious requirements.** Its output is **JSON Lines**,
one object per finding, not a single document like every other adapter — hence a
streaming `json.Decoder` (a `bufio.Scanner` caps a token at 64KB, and a secret
inside a minified bundle blows past any limit you'd pick). `--no-update` is
mandatory or it downloads and re-execs a newer build of itself mid-scan, so the
pinned version is not the version that ran. **Never pass `--fail`**: omitting it
makes findings exit 0, which is the property `--exit-code 0` buys for Trivy. And
`filesystem` walks `.git`, so the default exclude list is load-bearing — a secret
in a packfile gets a path that churns on every gc, and the path is a fingerprint
input.

**A secret's plaintext must never reach a `Finding`.** `Raw`, `RawV2`, and
`SecretParts` all carry it; they are read to derive a `sha256:` identity digest
and discarded. Reports are written to disk and served over HTTP, so a Finding
holding a secret makes a secret scan a second copy of every secret. Note that
TruffleHog's own `Redacted` field is *not* safe to forward verbatim — for
`PrivateKey` it is the PEM header plus 32 characters of key body — so it is
capped before display. Do not key identity on `Redacted` either: it is populated
by some detectors and not others, so a conditional there means somebody else's
release changes our fingerprints.

**Binary resolution has four locations, and adapters must not reimplement it.**
`toolpath.Lookup` searches an explicit `--<tool>-binary` path, then PATH, then
beside the pindrop binary, then `~/.pindrop/bin` where `pindrop setup` installs.
That function used to be copy-pasted into all four adapters and had already
drifted. PATH deliberately beats the managed directory, so a user's own Trivy
keeps winning — which also means an *old* Trivy on PATH still trips the version
floor rather than falling through to ours. `pindrop setup --check` prints the
winning origin per tool precisely because that case is otherwise baffling.

**Bumping a scanner version means running `make manifest`.** `pindrop setup`
verifies every download against a SHA-256 digest committed in
`internal/toolinstall/manifest.json`; a stale manifest is not a warning, it is
every install failing on a checksum mismatch. A test asserts the manifest agrees
with the Makefile's pins, so forgetting fails `make test` rather than a user's
first run. Opengrep publishes no upstream checksum file — only sigstore
signatures — so its digest is trust-on-first-pin and the generator prints a
`cosign verify-blob` command to check by hand
([ADR 0010](docs/decisions/0010-managed-scanner-installation.md)).

**The manifest gives immutability, not provenance.** It stops an asset being
swapped after we pinned it, which is the retagged-release case the Trivy incidents
were. It cannot detect a release that was already malicious when the digest was
captured. Do not oversell it in user-facing text.

**Never add a `--skip-verify` to setup.** A security product with an escape hatch
around its own integrity check has not shipped one. `--<tool>-binary /path`
already covers the legitimate need.

**Opengrep needs a UTF-8 locale forced into its environment.** It is a
Nuitka-compiled CPython program, so it derives its text encoding from the locale;
with no `LANG`/`LC_ALL` — cron, systemd, slim containers, some CI runners — that
default is ASCII, and reading a bundled rule file containing an em dash dies with
`UnicodeDecodeError`. The symptom is the worst kind: the scan *succeeds* and
silently reports zero code findings. `utf8Env` sets `LC_ALL=C.UTF-8` unless the
inherited locale is already UTF-8. `PYTHONUTF8=1` does **not** work — the Nuitka
build ignores it. Note `--version` reads no rules, so Preflight cannot catch this.

**The scan display renders to stderr, and any concurrent stderr writer shreds
it.** stdout carries the report and must stay pipeable into `jq`. This works only
because every adapter buffers its child's stdout *and* stderr and OSV runs with
`--verbosity error` — an adapter that lets a child write to stderr would corrupt
every frame. `--log-level debug` therefore forces plain mode, since slog also
writes there. `internal/tui` is the only package allowed to import bubbletea or
lipgloss ([ADR 0011](docs/decisions/0011-bubbletea-for-progress.md)).

**The progress footer says "raw findings" on purpose.** It sums what each scanner
reported, before cross-tool dedup, so it is legitimately larger than the count the
table prints — 25 raw against 19 on the fixture. Renaming it to "findings" would
make the report look like it lost some.

**`scan.Observer` must stay free of presentation.** No colors, no display
strings, no cross-scanner ordering guarantee. Per-scanner ordering is total
because one scanner's events come from its own goroutine; ordering between
scanners is not, and a renderer must not assume it. Observers are called from
every scanner goroutine, so they must be concurrency-safe and must not block.

**Skipped scanners are indexed after the usable ones, not at their registry
index.** `scan.Run` reports on the usable slice, which is re-indexed from zero, so
a skipped row placed at its registry index gets overwritten by whichever usable
scanner lands on the same row. `replaySkipped` starts at `len(usable)`.

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
