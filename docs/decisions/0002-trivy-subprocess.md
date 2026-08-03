# 0002 — Run Trivy as a subprocess, not a library

**Status:** Accepted
**Date:** 2026-08-02

## Context

Trivy is written in Go and is Apache-2.0 licensed, so importing it as a library
looks obviously right — a single self-contained binary with no external tool to
install. That was in fact the initial plan for this project, and it was wrong.

## Decision

Invoke the `trivy` CLI as a subprocess. Parse its JSON with hand-written structs.

### The decisive argument

**Trivy downloads `trivy-db` from a remote OCI registry at runtime regardless of
how it is invoked.** Embedding the library produces a ~150 MB binary that still
phones home on first run. You pay the entire cost of embedding and get none of
the distribution benefit that motivated it.

Once that is understood, everything else is one-sided.

### Supporting evidence

**The Go API is explicitly unsupported.** From maintainer PR #9606: *"using
Trivy as a library is not recommended for community users."* That PR would have
created a real public/internal boundary; it was closed for inactivity in January
2026, leaving the whole `pkg/` tree exposed with no stability contract. There
are no SDK docs — discussion #8531 asking for them has no maintainer reply.

**The module is v0 with real churn.** `pkg/scanner` → `pkg/scan` already
happened. `driver.Provider` → `driver.Supplier` already happened. Every Trivy
bump is a potential compile break with no changelog written for library users.

**The dependency graph is disqualifying.** ~499 modules, 132 direct, including
20 AWS SDK modules (`service/ec2` among the largest generated Go packages in
existence), Azure and GCP SDKs, Helm v4, containerd, docker/cli, client-go, and
OPA — all linked in to scan a local directory. Build times, `go.sum` size,
supply-chain audit surface, and inherited CVE surface all balloon.

**It forces Go ≥ 1.26.3** on us and everyone who builds the project.

**Precedent points the same way.** Harbor's production scanner adapter,
`harbor-scanner-trivy`, does not import Trivy at all — it builds argv and calls
`exec.Command`. The only library consumers are Aqua's own projects, maintained
in lockstep with Trivy releases.

## Consequences

**Good:** 7.4 MB binary instead of ~150 MB. Fast builds. No Go version floor
from Trivy. A versioned, documented contract (`SchemaVersion: 2` plus
`--format json`) that moves far more slowly than the Go API. Users can upgrade
Trivy independently of Pindrop. Process isolation from Trivy crashes and OOMs.

**Cost:** Users must install Trivy. `Preflight` therefore has to fail with real
installation guidance rather than a raw exec error — there is a CI check
asserting exactly that.

## Implementation notes

```
trivy fs --scanners vuln,misconfig,secret,license \
         --format json --quiet --exit-code 0 <path>
```

- **`--exit-code 0` is essential.** Without it Trivy exits non-zero when it
  finds vulnerabilities, making "the tool failed" indistinguishable from "the
  code has bugs".
- **Hand-roll the structs.** Importing `trivy/pkg/types` for `Report` alone
  drags in `fanal/types`, `go-containerregistry`, and `sbom/core` — most of the
  tree — to save sixty lines.
- **Decode defensively.** `Results` is omitted entirely on a clean scan. Only
  `VulnerabilityID`, `PkgName`, `InstalledVersion`, and `Severity` are
  guaranteed populated.
- **Capture golden fixtures from the real tool.** This adapter originally read
  an `AVDID` field that appears in documentation and *not* in v0.72.0 output;
  the mistake survived until the fixture was regenerated from a real run.
- **Pin by version and verify checksums.** Trivy's release channel was
  compromised twice in 2026, including a malicious `v0.69.4` and a compromised
  `trivy-action` (CVE-2026-33634). CI pins `v0.72.0`.

## What would reverse this

Needing in-process control the CLI cannot express — custom analyzers, streaming
per-file callbacks, non-file artifact sources. Even then the runtime database
download means a self-contained binary is still not on offer.

The `scan.Scanner` interface keeps the blast radius small: only
`internal/scan/trivy` would change.
