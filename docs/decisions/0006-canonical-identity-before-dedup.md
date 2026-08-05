# 0006 — Canonicalize advisory IDs and package coordinates before fingerprinting

**Status:** Accepted
**Date:** 2026-08-05

## Context

[ADR 0002](0002-trivy-subprocess.md) settled how scanners run. This one settles a
problem that only appears once a *second* scanner runs, and that had to be
settled before Phase 1 persists anything.

`scan.Fingerprint` excludes the scanner name specifically so that two tools
reporting one problem collapse into one issue. On inspection, that is not
sufficient — it removes one obstacle to merging and leaves three others in place.
Trivy and OSV-Scanner describe the same npm vulnerability like this:

| | Trivy | OSV-Scanner |
|---|---|---|
| Advisory ID | `CVE-2024-21538` | `GHSA-3xgq-45jj-v275` (CVE in `aliases`) |
| Ecosystem | `gomod` | `Go` |
| Version | `v0.35.0` | `0.35.0` |

Every one of those differences changes the fingerprint. Enabling the second
scanner would therefore have roughly doubled the dependency findings a user sees
while adding no information — the exact noise multiplication the product exists
to prevent, shipped under the banner of better coverage.

The trap is that this looks like an adapter problem and is not. An adapter can
normalize its own tool's vocabulary, but "which of GHSA-3xgq-45jj-v275 and
CVE-2024-21538 is the identity" is a question about the domain model, and both
adapters must answer it identically without knowing about each other.

## Decision

Canonicalize identity inputs inside `internal/scan` before hashing, in
`canonical.go`:

- **`CanonicalAdvisoryID(ruleID, aliases)`** — a CVE ID wins whenever one is
  available, otherwise the reported ID is kept. CVE is the only namespace all
  advisory databases cross-reference.
- **`CanonicalEcosystem`** — maps scanner vocabularies onto Package URL types, an
  existing standard rather than one we invented.
- **`CanonicalVersion`** — strips Go's `v` prefix. Nothing else.

Add `Finding.Aliases`, which adapters populate from their tool's output, and
`Finding.Scanners`, which `Dedup` populates with every adapter that reported the
finding. `Finding.Agreement()` reads the latter as the confidence signal.

`scan.Dedup` groups by fingerprint and merges. `scan.Findings` calls it, because a
flat list of every scanner's raw output is never what a user should see.

### Canonicalization must not depend on which scanners ran

This is the constraint that shaped the design. The obvious implementation is a
union-find over all findings' IDs and aliases, resolving each cluster to one
representative. It is strictly more powerful and it is wrong: the representative
would depend on the set of findings in the scan, so enabling a new scanner —
or a scan where one tool happened to fail — would rewrite the identity of
existing findings and orphan their triage decisions.

Preferring CVE is weaker but depends only on a single finding's own identifiers.
Both tools converge on it independently, which is all that is needed.

### Merging is grouping, not similarity matching

Because canonicalization happens before hashing, duplicates arrive at `Dedup`
already sharing a fingerprint. There is no similarity threshold to tune and no
near-miss category. Every merge rule is order-independent, so the merged output
is byte-identical regardless of which scanner finishes first — required, since
these values are about to be persisted and diffed.

Where tools disagree, the higher severity and the more specific location win, and
aliases and references are unioned. Under-reporting severity is the more damaging
error, because ranking decides whether the user ever sees the finding.

## Outcome, measured

The OSV-Scanner adapter landed immediately after this and confirmed the design on
real output rather than in principle. On `testdata/vulnerable-app`: Trivy 8 raw
findings, OSV-Scanner 6, **14 raw merging to 8** — the same count Trivy alone
produced, with four now corroborated by both tools.

Two effects were not anticipated:

- **Canonicalization reproduced OSV-Scanner's own grouping for free.** OSV reported
  five lodash advisories and groups them into three issues; preferring the CVE
  collapsed them into exactly those three, without Pindrop reading its `groups`
  field for identity at all.
- **The degradation mode showed up and behaved as designed.** A single OSV advisory
  can list *two* CVEs as aliases (`GHSA-35jh-r3h4-6jhm` names both
  `CVE-2021-23337` and `CVE-2026-4800`). `CanonicalAdvisoryID` resolves it to the
  lower-sorting one, so Trivy's separate report of the other has nothing to pair
  with and stays a duplicate. A visible duplicate, not a wrong merge — the trade
  this ADR chose. Fixing it needs cross-finding alias clustering, which is rejected
  above.

A third obstacle surfaced during implementation that this ADR had not listed:
**OSV-Scanner reports absolute source paths where Trivy reports relative ones.**
Since the manifest path is a fingerprint input, an absolute path makes identity
depend on the checkout directory — it differs between a laptop and CI and never
merges. `osv.relativePath` normalizes it in the adapter, because it is a property
of that tool's output rather than of the domain model.

## Consequences

**This changes existing fingerprints,** for any finding whose ecosystem or version
was previously non-canonical — every Go finding, among others. Nothing is
persisted in Phase 0, so the cost today is zero. After Phase 1 it would be a data
migration. That timing is why this landed before persistence rather than
alongside the scanner that motivated it.

**Adapters gain an obligation.** Any adapter whose tool reports advisory aliases
must populate `Finding.Aliases`, or cross-tool merging silently stops working for
its findings. This is now in [scanners.md](../architecture/scanners.md).

**Cross-tool SAST dedup is still unsolved.** Location-scoped identity uses the raw
rule ID, because two SAST engines' rule IDs for "SQL injection" have no shared
namespace to canonicalize onto. Opengrep and Trivy will report overlapping code
findings as separate issues. Deliberately deferred: no defensible mapping exists,
and inventing one risks merging unrelated findings.

**Ecosystem coverage is a maintenance surface.** An unmapped vocabulary degrades to
"does not merge", never to "merges wrongly", so the failure is a visible duplicate
rather than a hidden issue. That is the correct direction, but the table needs
extending as scanners are added.

## Alternatives considered

**Canonicalize in each adapter.** Rejected: both adapters must make identical
choices about a shared model, so the logic belongs in `internal/scan`. Duplicating
it guarantees drift, and drift here manifests as duplicate findings rather than a
compile error.

**Resolve aliases against the OSV.dev API.** Correct in the general case and
rejected on principle: it makes fingerprinting depend on a network call, so
identity would vary with connectivity and with upstream data changes. Fingerprints
must be computable offline and forever.

**Union-find alias clustering.** Rejected above — more merges, at the cost of
identity that changes when the scanner set changes.

**Include the scanner name and dedup by fuzzy matching instead.** Rejected: it
inverts the design. Exact grouping on a canonical identity has no tuning
parameters and no false merges; similarity matching has both.
