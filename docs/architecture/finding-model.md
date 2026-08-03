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
    RuleID      string      // "CVE-2024-21538", "DS-0002", "github-pat"
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
  and Grype reporting the same CVE, must collapse into one issue. Agreement
  between tools becomes a confidence signal rather than a duplicate.

### Identity differs by category

| Category | Inputs |
|---|---|
| `vulnerability`, `license` | rule ID + package name + version + ecosystem + manifest path |
| `secret`, `misconfiguration`, `code` | rule ID + file path + normalized snippet |

Dependency findings ignore the line entirely — the same CVE in the same package
version is the same problem regardless of where the manifest sits. But the
manifest *path* is included, so the same vulnerable package in two services of a
monorepo stays two issues: different owners, different pull requests.

Location-scoped findings hash the normalized surrounding source instead.
`NormalizeSnippet` collapses whitespace runs and trims, so re-indenting or
running a formatter does not change identity, while changing actual tokens does.

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
