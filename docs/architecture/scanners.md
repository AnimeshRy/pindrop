# Scanners

## The contract

```go
type Scanner interface {
    Name() string
    Preflight(ctx context.Context) error
    Scan(ctx context.Context, target Target) (Result, error)
}
```

Rules every adapter must honor:

1. **`Name()` is persisted.** Lowercase, constant across versions.
2. **`Preflight` wraps `scan.ErrUnavailable`** and its message is shown directly
   to the user, so it must say how to fix the problem. Use
   `scan.UnavailableError` with a `Hint`.
3. **Every returned finding has `Scanner` and `Fingerprint` set.**
   **Populate `Aliases` whenever the tool reports other identifiers for the same
   advisory.** Omitting them does not fail any test — it silently stops this
   tool's findings from merging with another's, which is the failure the product
   is supposed to prevent. See
   [ADR 0006](../decisions/0006-canonical-identity-before-dedup.md).
4. **No findings is not an error.** Return an empty slice and a nil error; a
   non-nil error means the tool itself failed. This includes finding nothing to
   scan: a repository with no lockfiles is a successful empty scan.
   **A missing binary is reported through `Preflight`, not `Scan`** — `scan.Usable`
   drops unavailable scanners so one absent optional tool degrades coverage
   instead of aborting the run.
5. **Safe for concurrent use** — `scan.Run` fans scanners out in parallel.
6. **Respect `ctx`.** Use `exec.CommandContext` so cancellation kills the child
   process rather than leaking it.

## Subprocess, not library

Adapters shell out. For Trivy specifically this is a researched decision with a
decisive argument — Trivy downloads its vulnerability database at runtime no
matter how you invoke it, so embedding buys no self-contained binary while
costing a ~500-module dependency graph. See
[ADR 0002](../decisions/0002-trivy-subprocess.md).

The general form of the argument holds for most scanners, and there is a hard
constraint for at least one: TruffleHog is AGPL-3.0, so importing it would
infect the whole codebase.

Practical rules for subprocess adapters:

- Pass the tool's "don't fail on findings" flag (`--exit-code 0` for Trivy) so a
  non-zero exit unambiguously means the tool broke. **Not every tool has one** —
  OSV-Scanner signals findings through the exit code with no way to disable it, so
  its adapter classifies codes instead: 0 and 1–126 are completed scans, 128 is
  "no manifests found" (a valid empty scan, not an error), and 127 plus 129–255
  are real failures. Getting this wrong reports every vulnerable repository as a
  broken tool.
- Hand-roll the result structs. Importing the tool's own types to save sixty
  lines drags in its entire dependency tree.
- Decode defensively — fields are usually `omitempty`, and top-level arrays are
  often absent rather than empty.
- Capture stderr separately and include a trimmed tail in error messages.

## Adding a scanner

1. Create `internal/scan/<tool>/`.
2. `<tool>.go` — the `Scanner` implementation, with functional options
   (`WithBinary`, `WithTimeout`, …). Follow `trivy/trivy.go`.
3. `report.go` — hand-written structs mirroring the tool's output. Capture real
   output; do not write them from documentation. (The Trivy adapter originally
   read an `AVDID` field that documentation mentioned and the tool does not
   actually emit.)
4. `convert.go` — map into `scan.Finding`, including severity vocabulary.
5. `testdata/report.json` — a **captured** golden report, so tests run without
   the tool installed. Note in the file which parts are captured and which, if
   any, are derived.
6. Register it in the slice in `internal/cli/scan.go`. That is the only place
   outside the new package that changes.

A tool that needs rules or policies of its own keeps them inside its package and
embeds them, as `opengrep/rules.go` does with `//go:embed all:rules`. Anything the
tool must read from disk gets extracted to a fresh temporary directory per scan —
`scan.Run` fans scanners out in parallel, so a shared mutable directory is a race.

## Tool inventory and licensing

Licensing constrains what we can do, and getting it wrong is expensive.

| Tool | License | Language | Status | Notes |
|---|---|---|---|---|
| **Trivy** | Apache-2.0 | Go | **In use** | Subprocess. SCA, IaC, secrets, licenses in one invocation |
| **OSV-Scanner** | Apache-2.0 | Go | **In use** | Second SCA opinion on a different advisory corpus, and the only free source of reachability — see below |
| **Opengrep** | LGPL-2.1 | OCaml | **In use** | SAST, on rules we write ourselves. Preferred over Semgrep CE — see below |
| **TruffleHog** | **AGPL-3.0** | Go | Phase 2 | Secrets, verified-only. **Subprocess only — never import** |
| **zizmor** | MIT | Rust | Phase 2 | GitHub Actions workflows. Small scope, near-zero noise |
| **Trivy `k8s`** | Apache-2.0 | Go | Phase 2 | EKS posture with no new adapter — a new `Target` kind |
| **Kubescape** | Apache-2.0 | Go | Later | CNCF Incubating. Purpose-built K8s posture, if Trivy's proves thin |
| **Prowler** | Apache-2.0 | Python | Later | AWS/Azure/GCP posture. **Needs a curated check set first** — see below |
| **Gitleaks** | MIT | Go | Deferred | Regex secrets; a third opinion of a kind Trivy already provides. Useful for pre-commit hooks |
| **Syft** | Apache-2.0 | Go | Maybe | SBOM generation. A feature, not a scanner |
| **Grype** | Apache-2.0 | Go | Skipped | Draws largely the same NVD/GHSA sources as Trivy — full dedup cost, little new signal |
| **KICS / Checkov / Terrascan** | Apache-2.0 | Go / Python | Skipped | Trivy covers IaC; overlap without new signal is noise |
| **OWASP Dependency-Check** | Apache-2.0 | Java | Skipped | Java-centric, slow, high false-positive rate |
| **Bandit / gosec / Brakeman** | various | various | Skipped | Per-language; Opengrep subsumes them with one adapter |

### Measured result of adding the second and third scanners

On `testdata/vulnerable-app`:

| | Trivy + OSV | + Opengrep |
|---|---|---|
| Trivy raw findings | 8 | 8 |
| OSV-Scanner raw findings | 6 | 6 |
| Opengrep raw findings | — | 11 |
| Raw total | 14 | 25 |
| **After `scan.Dedup`** | **8** | **19** |
| Findings with `Agreement() == 2` | 4 | 4 |

Adding an entire **second** scanner added **zero** net findings — its six raw
findings all merged. Four vulnerabilities carry `Agreement() == 2`, which is new
information at no cost in noise.

The **third** behaves differently and is supposed to: all eleven of Opengrep's
findings are new, because none of them can merge with anything. They are the first
findings in the product that are not about a dependency or a config file, so there
is nothing for them to coincide with. Overlap is the thing to watch when a scanner
duplicates an existing one's domain; a scanner that opens a *new* domain is
measured on precision instead, which is the healthy-repo test below.

That test is the one that matters here. The bundled ruleset reports **zero**
findings against `internal/`, `cmd/`, and `web/src/` — the fixture files exist
precisely so the adapter has something to find. Eleven findings on 3 deliberately
vulnerable files and 0 on ~60 real source files is the ratio a curated set is for.
Re-measure both numbers after wiring any further scanner, and after adding any
rule; if the healthy-repo count moves off zero, a rule is too broad.

Two Trivy findings (`CVE-2026-4800`, `CVE-2026-2950`) stayed unmerged. Both are
cases where a single OSV advisory lists *two* CVEs as aliases, so
`CanonicalAdvisoryID` resolves it to the lower-sorting one and Trivy's report of
the other has nothing to pair with. This is the documented degradation mode: a
visible duplicate, never a wrong merge. It cannot be fixed by clustering aliases
across findings without making identity depend on which scanners ran — see
[ADR 0006](../decisions/0006-canonical-identity-before-dedup.md).

Worth noting the mechanism reproduced OSV-Scanner's own grouping for free:
OSV reported five lodash advisories, which canonicalization collapsed to the same
three issues OSV itself groups them into, without Pindrop reading its `groups`
field for identity.

### Why OSV-Scanner came before a second secrets or SAST tool

Two reasons, and the second is the one that matters.

It is the **cheapest adapter** — Go, Apache-2.0, clean JSON — while overlapping
Trivy heavily enough to exercise cross-tool dedup against real data on the first
run. A scanner that merges correctly is the thing Phase 2 has to prove.

It is also the **only free source of reachability analysis**: `--call-analysis`
covers Go (via the `govulncheck` library) and Rust. Pindrop leaves it **off by
default** — it compiles the packages under analysis, turning a one-second lockfile
parse into a build that needs a working toolchain for the target language. Enable
it with `--call-analysis`. Phase 6's prioritization story rests on reachability actually cutting
noise, and the vision doc names that as a falsifiable premise. This lets it be
tested cheaply and early instead of after a phase has been committed to it.

Note that OSV reports advisories under GHSA or GO IDs with the CVE in `aliases`,
and names ecosystems differently from Trivy. Merging those is what
[ADR 0006](../decisions/0006-canonical-identity-before-dedup.md) exists for.

### Opengrep needs a rule strategy, not just an adapter

Opengrep ships **no rules**, and neither existing corpus can be redistributed by
a commercial product: `opengrep-rules` carries the Commons Clause, registry rules
carry the Semgrep Rules License. So Pindrop embeds ten of its own in
`internal/scan/opengrep/rules/`, extracted to a temporary directory per scan
because `--config` needs a filesystem path. `--opengrep-rules` replaces them with
anything the user prefers, registry shorthands included — their machine, their
licensing call. Full reasoning in
[ADR 0007](../decisions/0007-first-party-opengrep-rules.md); rule-authoring
conventions in `internal/scan/opengrep/rules/README.md`.

Four things about this adapter that are not guessable from the tool's docs, all
verified against v1.26.0:

- **Omitting `--config` is not "no rules", it is `auto`** — a ~2.4 MB download of
  Semgrep-licensed rules from `semgrep.dev` on every scan. One missing flag is
  both a network dependency and a licensing violation, with no error.
- **`--no-rewrite-rule-ids` is mandatory.** By default Opengrep prefixes each
  rule's id with the path of the file it came from. `check_id` becomes
  `Finding.RuleID`, which is a fingerprint input — so the default makes identity
  depend on the rules directory's layout, and reorganizing it would orphan every
  triage decision. Even with the flag, **renaming a rule is a data migration.**
- **`--no-git-ignore` is mandatory too.** Opengrep scans only git-tracked files by
  default. A target that is not a repository, or a working tree with uncommitted
  code, otherwise scans to a silent, successful zero findings.
- **Findings do not produce a non-zero exit.** The inverse of the Trivy and
  OSV-Scanner problem: `error_on_findings` defaults to false, so there is no
  `--exit-code 0` equivalent to pass and `--error` must never be passed. Non-zero
  therefore means something broke, and `osv.resultExit`'s job here is deciding how
  badly: exit 3 (one unparseable source file) keeps the report, because one broken
  file must not cost a repository its analysis, while 4, 5, and 7 mean the ruleset
  failed to load — normally *our* ruleset, so they must be loud.

`extra.lines` must reach `Location.Snippet`. It is the only thing distinguishing
two hits of one rule in one file, and dropping it merges them silently. Note the
schema will mislead you here: `semgrep_output_v1.atd` marks `lines`,
`fingerprint`, and `metavars` as requiring a login, which is true of upstream
Semgrep since 1.98 and false of Opengrep — emitting them unconditionally is much
of why the fork exists. Capture the fixture; do not write it from the schema.

### Cloud and cluster findings break the location model

Trivy, OSV-Scanner, Opengrep, and TruffleHog all report findings anchored to a
file. Kubernetes and cloud posture findings are not: a permissive security group
or an over-broad IRSA role is identified by resource ARN and check ID, and the
resource may be ephemeral. A fingerprint keyed on an EKS node's instance ID would
report every finding as fixed-and-reintroduced on the next node rotation — the
line-number failure in a new coordinate system.

**A resource-identity scheme has to be designed before Phase 1 persists anything**,
or adding cloud scanning later is a migration. It needs its own ADR.

### Prowler is the largest noise risk in this table

600 checks across 44 compliance frameworks. Pointed at one AWS account, a CIS
benchmark run emits hundreds of findings, most compliance-shaped rather than
exploitable. This is the single tool most likely to turn Pindrop into the "worse
DefectDojo" its vision doc names as the falsification condition.

Unlike `actionableLicense`, the filter cannot be worked out after wiring it up:
the curated check subset has to be decided first, because there is no severity
signal in the output that separates "publicly exposed S3 bucket" from "bucket
lacks an access-logging tag".

### Two specific traps

**TruffleHog is AGPL-3.0.** Running it as a separate process is fine — separate
processes are not derivative works. Importing it as a Go library would place the
entire Pindrop codebase under AGPL, which is incompatible with the commercial
plan. This must never happen by accident.

It is chosen over Gitleaks anyway, because its verifier modules make read-only API
calls that prove whether a credential is **live** — the "12 secrets → 1 live key"
row in the vision doc, and a signal no amount of correlation can synthesize from
regex hits. Trivy already does regex-and-entropy secrets; a second regex engine
adds matches, not information.

**Verification sends discovered secrets to third-party APIs.** That is a product
decision, not an implementation detail: it must be opt-in and disclosed, and it
needs its own ADR before the adapter ships.

**Semgrep's rule registry is not open source.** Semgrep CE itself is LGPL, but
the registry rules moved to a restrictive license that prohibits building
competing products. That is exactly what we are doing. Use **Opengrep** (the
2025 fork) or curate our own rules; do not ship Semgrep's registry. This is
settled by [ADR 0007](../decisions/0007-first-party-opengrep-rules.md) — see
the Opengrep section below for the flag that makes the trap concrete.

**Trivy's release channel was compromised twice in 2026** (a malicious `v0.69.4`
and a compromised `trivy-action`). Pin by version and verify checksums in any
install path we control. CI pins `v0.72.0` explicitly.

## Filtering is part of the adapter's job

An adapter that faithfully forwards everything its tool reports is not finished.
Trivy's license scanner classifies **every** license it identifies, so enabling
it naively produced 24 MIT/Apache/BSD/ISC entries against 8 real problems when
scanning Pindrop itself — a 4x noise multiplier from one sub-scanner.

`actionableLicense` in `trivy/convert.go` keeps only `forbidden`, `restricted`,
and `reciprocal` — the copyleft categories that can actually oblige a commercial
product to do something. `notice`, `permissive`, `unencumbered`, and `unknown`
are dropped. A user who wants the full inventory wants an SBOM, which is a
different feature.

`actionable` in `opengrep/convert.go` is the same idea for SAST, and it exists
mainly to protect the `--opengrep-rules` path: it drops matches the author already
suppressed with a `nosemgrep` comment, the `EXPERIMENT` and `INVENTORY`
severities, and rules declaring their own confidence as `LOW`. Against the
bundled ruleset it is nearly a no-op; against a registry corpus of several hundred
rules it is what stands between the user and the noise.

**Apply the same test to every new adapter:** after wiring it up, scan a
healthy repository. If the count jumps by more than a handful, the adapter is
forwarding noise and needs a filter before it ships.

## Severity mapping

Each tool has its own vocabulary; adapters normalize. Trivy's mapping lives in
`trivy/convert.go`:

| Tool value | `scan.Severity` |
|---|---|
| `CRITICAL` | `critical` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFO` | `info` |
| anything else | `unknown` |

Unrecognized values map to `unknown` rather than being guessed at. A wrong
severity is worse than an absent one, because it distorts ranking.

**OSV-Scanner reports a number, not a word.** It has no qualitative severity
vocabulary: the only severity figure in its output is `groups[].max_severity`, a
CVSS base score as a string. `osv/convert.go` maps it using the CVSS v3.1
qualitative bands:

| CVSS score | `scan.Severity` |
|---|---|
| 9.0 – 10.0 | `critical` |
| 7.0 – 8.9 | `high` |
| 4.0 – 6.9 | `medium` |
| 0.1 – 3.9 | `low` |
| 0.0 | `info` |
| absent or unparseable | `unknown` |

Using the standard bands rather than an invented mapping is what makes the two
tools agree: on the bundled fixture this reproduces Trivy's grading for all six
advisories they both report. Severity sits on the group, so every advisory in a
group shares one, and an advisory in no group is left `unknown`.

**Opengrep has two severity vocabularies, and both are valid.** `ERROR`/`WARNING`/
`INFO` are the original set; `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` were added upstream
in 1.72 and a rule may use either today. `opengrep/convert.go` handles all of
them:

| Tool value | `scan.Severity` |
|---|---|
| `CRITICAL` | `critical` |
| `ERROR`, `HIGH` | `high` |
| `WARNING`, `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFO` | `info` |
| anything else | `unknown` |

`ERROR → high` and `WARNING → medium` are the equivalences upstream states in its
own schema, not a guess of ours. `EXPERIMENT` and `INVENTORY` are also legal
values but never reach this function: `actionable` drops them first, because they
mark rules used for rule development and for cataloguing what a codebase contains
rather than for finding defects.

Note that `metadata.confidence`, `likelihood`, and `impact` use a *third* scale
(`LOW`/`MEDIUM`/`HIGH`) that is not interchangeable with severity. Only
`confidence` is read, and only to drop self-declared low-confidence rules.
