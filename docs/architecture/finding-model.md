# The finding model

Defined in [`internal/scan/finding.go`](../../internal/scan/finding.go) and
[`fingerprint.go`](../../internal/scan/fingerprint.go).

This is the most important document in the repository. The `Finding` type and
its fingerprint are the product; everything else is plumbing around them.

## Why normalize at all

Every scanner emits a different shape:

```
Semgrep:  {check_id, path, start.line, extra.message, extra.severity}
Trivy:    {VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity}
Gitleaks: {RuleID, File, StartLine, Secret, Entropy}
```

Without a common model the dashboard is four dashboards in a trenchcoat, nothing
can be deduplicated across tools, and every new scanner means new UI.

## The type

```go
type Finding struct {
    Fingerprint string      // derived identity — see below
    Scanner     string      // "trivy" — provenance only
    Scanners    []string    // every tool that reported it; set by Dedup
    RuleID      string      // "CVE-2024-21538", "DS-0002", "github-pat"
    Aliases     []string    // other IDs for the same advisory — affects identity
    Category    Category    // vulnerability|secret|misconfiguration|code|license
    Severity    Severity    // unknown|info|low|medium|high|critical
    Title       string
    Message     string
    Location    Location    // Path, StartLine, EndLine, Snippet
    Package     *PackageRef // nil unless dependency-scoped
    FixedIn     string
    References  []string
}
```

`Aliases` is not descriptive — it feeds [`CanonicalAdvisoryID`](#canonicalization)
and therefore the fingerprint. `Scanners` is: `len(Scanners)`, read via
`Agreement()`, is the confidence signal for two tools independently agreeing.

`Severity` and `Category` are string-typed rather than integer enums so JSON
output stays readable and stable across releases. `Severity.Rank()` supplies
ordering; the `exhaustive` linter enforces that switches cover every value,
because a missed case renders as a silent blank in the UI.

## Fingerprinting

**The problem it solves.** Scan #46 reports SQL injection at `api/users.go:42`.
Someone adds an import; scan #47 reports it at line 43. If identity included the
line number, Pindrop would announce one issue fixed and one new issue
introduced. Do that once and the user stops believing anything the tool says.

The property that matters most: **a triage decision must be permanent.** Mark
something a false positive, reformat the file, rescan — it stays marked.
Everything below exists to make that true.

### Two inputs are deliberately excluded

- **Line numbers.** Insertions above a finding must not change its identity.
- **The scanner name.** Gitleaks and TruffleHog finding the same key, or Trivy
  and OSV-Scanner reporting the same CVE, must collapse into one issue. Agreement
  between tools becomes a confidence signal rather than a duplicate.

### Canonicalization

Excluding the scanner name removes one obstacle to merging and leaves three in
place. Trivy and OSV-Scanner describe one Go vulnerability like this:

| | Trivy | OSV-Scanner |
|---|---|---|
| Advisory ID | `CVE-2025-22870` | `GO-2025-3503` (CVE in `aliases`) |
| Ecosystem | `gomod` | `Go` |
| Version | `v0.35.0` | `0.35.0` |

Each difference would produce a separate fingerprint, so `canonical.go` normalizes
all three before hashing:

- **`CanonicalAdvisoryID`** prefers a CVE whenever one is available — the only
  namespace every advisory database cross-references. Otherwise the reported ID
  stands.
- **`CanonicalEcosystem`** maps scanner vocabularies onto Package URL types.
  Unknown values pass through lowercased, so an unmapped ecosystem degrades to
  "does not merge", never to "merges wrongly".
- **`CanonicalVersion`** strips Go's `v` prefix, and nothing else. Comparing
  versions properly needs per-ecosystem semantics, and getting that wrong merges
  unrelated versions — worse than a duplicate.

**Canonicalization depends only on a single finding's own fields, never on the
rest of the scan.** Clustering aliases across findings would merge more, but the
chosen identity would then shift when the scanner set changed, orphaning triage
decisions. See [ADR 0006](../decisions/0006-canonical-identity-before-dedup.md).

Location-scoped findings keep their raw rule ID. Two SAST engines' identifiers for
"SQL injection" share no namespace to canonicalize onto, so cross-tool SAST dedup
remains unsolved and deliberately so.

### Deduplication

`scan.Dedup` groups findings by fingerprint and merges each group; `scan.Findings`
calls it, because a flat list of every scanner's raw output is never what a user
should see.

Because canonicalization happens before hashing, duplicates arrive already sharing
an identity. Merging is grouping, not similarity matching — no threshold to tune,
no near-miss category, no false merges. Where tools disagree the higher severity
and the more specific location win, and aliases and references are unioned. Every
rule is order-independent, so output is identical regardless of which scanner
finishes first — required, since these values get persisted and diffed.

A finding with an empty fingerprint passes through untouched rather than joining a
group, so an adapter bug surfaces as duplicate rows instead of being hidden.

### Identity differs by category

| Category | Inputs |
|---|---|
| `vulnerability`, `license` | canonical advisory ID + package name + canonical version + canonical ecosystem + manifest path |
| `secret`, `misconfiguration`, `code` | rule ID + file path + normalized snippet |

Dependency findings ignore the line entirely — the same CVE in the same package
version is the same problem regardless of where the manifest sits. But the
manifest *path* is included, so the same vulnerable package in two services of a
monorepo stays two issues: different owners, different pull requests.

Location-scoped findings hash the normalized surrounding source instead.
`NormalizeSnippet` collapses whitespace runs and trims, so re-indenting or
running a formatter does not change identity, while changing actual tokens does.

**For secrets, the snippet is not source text.** It cannot be: a report is
written to disk and served over HTTP, so the offending text is the one thing that
must not be stored. The TruffleHog adapter puts a `sha256:` digest of the
credential there instead — computed inside the adapter, from a plaintext that is
then discarded. It behaves identically for identity purposes: stable across runs,
distinct for two different credentials in one file, and unchanged when the file is
edited above them.

Two consequences worth knowing. The digest means secret findings from different
engines cannot merge, because no two secret scanners produce the same snippet
string — Trivy stores its own redacted match there. And a scanner's own
"redacted" rendering is not a substitute: it is per-detector implementation rather
than schema, so keying identity on it would let an upstream release change our
fingerprints. See
[ADR 0008](../decisions/0008-trufflehog-verification-opt-in.md).

Hash is SHA-256 truncated to 16 bytes, hex-encoded — 32 characters. Standard
library only; no `xxhash` dependency for something this small.

### Known trade-off

When a scanner reports no snippet, two hits of the same rule in the same file
merge into one finding. That is intentional: merging loses a little detail and
is recoverable, whereas a fingerprint that churns on every edit destroys the
feature entirely.

### Changing this function is a data migration

Every stored triage decision is keyed by fingerprint. Altering the algorithm
orphans all of them. If it ever must change, version the output and migrate
deliberately — the SARIF renderer already namespaces it as
`pindropFingerprint/v1` in anticipation.

`fingerprint_test.go` is the specification. It asserts stability across line
shifts, reindentation, formatter runs, scanner substitution, severity
re-grading, and advisory rewrites — and asserts *distinction* across different
CVEs, versions, ecosystems, paths, and actual code changes.

## Issue lifecycle

Phase 0 computes fingerprints but does not store them, so nothing below is
implemented yet. It is the target Phase 1 builds toward:

```
NEW ──► OPEN ──┬──► RESOLVED ──► REGRESSED ──► OPEN
               ├──► FALSE_POSITIVE   (sticky, forever)
               └──► ACCEPTED_RISK    (sticky, optionally expiring)
```

- **New** — fingerprint not seen in any prior scan
- **Still open** — present in both the previous and current scan
- **Resolved** — present previously, absent now
- **Regressed** — previously resolved, present again

`FALSE_POSITIVE` and `ACCEPTED_RISK` must survive every subsequent scan without
the user reconfirming. That is the whole point.

## Extending the model

Before adding a field, ask whether it affects identity.

- **Descriptive** (title, message, references, CVSS) — safe, does not touch the
  fingerprint.
- **Identifying** (a new coordinate that distinguishes two otherwise-identical
  findings) — changes the fingerprint, and therefore is a migration.

Do not add fields that exist only to satisfy one output format. SARIF's
vocabulary stays in `internal/report/sarif.go`.
